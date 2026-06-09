"""Active database lifecycle helpers for the storage DB commandlet.

Provides file creation, encryption conversion, passphrase prompting, backup,
and active-store replacement helpers.

Used by:
- `plugins.storage.db`: command handlers delegate DB lifecycle operations here.
- storage runner tests: continue importing public helpers through
  `plugins.storage.db` compatibility re-exports.
"""

from __future__ import annotations

import getpass
import os
from datetime import datetime
from pathlib import Path

from bywaf.config import Settings
from bywaf.db import EventStore, export_encrypted_database, export_plaintext_database
from bywaf.operator_state import save_ad_hoc_active_database
from bywaf.plugin import CommandContext

from .db_paths import database_related_paths

ENCRYPTION_VAR = "encryption"


def copy_plain_database(source: Path, destination: Path) -> None:
    """Copy a plaintext SQLite DB with the SQLite backup API."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    # backup() is safer than filesystem copying while the source may have an
    # open connection or WAL sidecars.
    with EventStore(source).connect() as source_conn:
        with EventStore(destination).connect() as dest_conn:
            source_conn.backup(dest_conn)


def encrypt_active_database(context: CommandContext) -> None:
    """Convert the active plaintext database file to SQLCipher encryption."""
    db = context.require_db()
    require_foreground_conversion(context, "db encrypt")
    if db.encrypted:
        raise ValueError("active database is already encrypted")
    passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    temp_path = temporary_database_path(db.path, "encrypt")
    db.checkpoint()
    # Convert into a sidecar first, validate it, then atomically replace the
    # active DB file.
    export_encrypted_database(db.path, temp_path, passphrase)
    EventStore(temp_path, passphrase=passphrase).table_counts()
    replace_database_file(db.path, temp_path)
    replace_active_store(context, EventStore(db.path, passphrase=passphrase))


def decrypt_active_database(context: CommandContext) -> None:
    """Convert the active encrypted database file to plaintext SQLite."""
    db = context.require_db()
    require_foreground_conversion(context, "db decrypt")
    if not db.encrypted or db.passphrase is None:
        raise ValueError("active database is already plaintext")
    confirmation = input("Decrypt active database and remove at-rest protection? type YES: ")
    if confirmation != "YES":
        raise ValueError("decryption cancelled")
    temp_path = temporary_database_path(db.path, "decrypt")
    db.checkpoint()
    # As with encryption, write and validate a replacement before touching the
    # active file.
    export_plaintext_database(db.path, temp_path, source_passphrase=db.passphrase)
    EventStore(temp_path).table_counts()
    replace_database_file(db.path, temp_path)
    replace_active_store(context, EventStore(db.path))


def rekey_active_database(context: CommandContext) -> None:
    """Change the passphrase for the active encrypted database."""
    db = context.require_db()
    require_foreground_conversion(context, "db rekey")
    if not db.encrypted:
        raise ValueError("db rekey requires an encrypted database")
    passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    db.rekey(passphrase)
    replace_active_store(context, EventStore(db.path, passphrase=passphrase))


def new_active_database(
    context: CommandContext,
    *,
    file: Path | None,
    encrypt: bool,
    force: bool,
) -> None:
    """Create a fresh database file and switch the active session to it."""
    db = context.require_db()
    require_foreground_conversion(context, "db new")
    path = file or default_new_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if is_same_path(path, db.path):
        raise ValueError("db new cannot replace the active database file")
    if database_files_exist(path):
        if not force:
            raise ValueError(f"{path} already exists")
        # Preserve the main DB and sidecars before creating over the target.
        backup_existing_database(path)
    passphrase = None
    if encrypt or default_encryption_enabled(context):
        passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    new_db = EventStore(path, passphrase=passphrase)
    new_db.table_counts()
    replace_active_store(context, new_db)


def default_new_database_path() -> Path:
    """Return a timestamped DB path under the default Bywaf DB directory."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = Settings().database_dir / f"bywaf-{stamp}.sqlite3"
    if not database_files_exist(base):
        return base
    counter = 1
    while True:
        candidate = Settings().database_dir / f"bywaf-{stamp}-{counter}.sqlite3"
        if not database_files_exist(candidate):
            return candidate
        counter += 1


def default_encryption_enabled(context: CommandContext) -> bool:
    """Return whether session variables request encrypted new databases."""
    value = (context.vars.get(ENCRYPTION_VAR, "") or "").strip().lower()
    return value in {"1", "true", "yes", "on", "encrypted", "sqlcipher"}


def is_same_path(left: Path, right: Path) -> bool:
    """Compare paths after resolving lexical relative components."""
    return left.expanduser().resolve(strict=False) == right.expanduser().resolve(strict=False)


def database_files_exist(path: Path) -> bool:
    """Return True if the main DB or SQLite sidecar files exist."""
    return any(database_related_paths(path))


def backup_existing_database(path: Path) -> None:
    """Move an existing database and sidecars to timestamped backup names."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for source in database_related_paths(path):
        backup = source.with_name(f"{source.name}.bak-{stamp}")
        counter = 1
        while backup.exists():
            backup = source.with_name(f"{source.name}.bak-{stamp}-{counter}")
            counter += 1
        os.replace(source, backup)


def prompt_new_passphrase(prompt: str, confirmation_prompt: str) -> str:
    """Prompt twice for a new passphrase and require an exact match."""
    passphrase = getpass.getpass(prompt)
    confirmation = getpass.getpass(confirmation_prompt)
    if not passphrase:
        raise ValueError("passphrase cannot be empty")
    if passphrase != confirmation:
        raise ValueError("passphrases did not match")
    return passphrase


def require_foreground_conversion(context: CommandContext, command: str) -> None:
    """Reject DB file conversion from background jobs that cannot update the parent."""
    context.require_foreground(command)


def temporary_database_path(path: Path, operation: str) -> Path:
    """Return a same-directory temporary path for atomic DB replacement."""
    return path.with_name(f".{path.name}.{operation}.{os.getpid()}.tmp")


def replace_database_file(path: Path, replacement: Path) -> None:
    """Replace the main DB file and remove stale sidecar files."""
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            sidecar.unlink()
    os.replace(replacement, path)


def replace_active_store(context: CommandContext, db: EventStore) -> None:
    """Update the parent runner when the command is running in-process."""
    replacer = context.metadata.get("replace_db")
    if callable(replacer):
        # The REPL/API injects this callback so commandlets do not reach into
        # Runner internals directly.
        replacer(db)
    runner = context.metadata.get("runner")
    if getattr(runner, "project", None) is None:
        save_ad_hoc_active_database(db.path)
    context.db = db
