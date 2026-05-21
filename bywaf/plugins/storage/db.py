"""Database storage commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Exports or inspects the active Bywaf database from inside the runtime.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import getpass
import os
from argparse import Namespace
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

from bywaf.config import Settings
from bywaf.db import EventStore, export_encrypted_database, export_plaintext_database
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionSpec, argument, commandlet

DB_ACTIONS = ("checkpoint", "decrypt", "encrypt", "new", "path", "rekey", "status", "vacuum")
ENCRYPTION_VAR = "encryption"
DbActionHandler = Callable[[CommandContext, Namespace], None]


@commandlet(
    name="db",
    description="Manage the active Bywaf SQLite database.",
    usage="db <status|path|checkpoint|vacuum|new|encrypt|decrypt|rekey>",
    examples=("db status", "db new --file=client.sqlite3", "db encrypt", "db rekey"),
    capabilities=("db.manage", "db.raw", "filesystem.read", "filesystem.write", "framework.console.output"),
)
@argument("action", "database operation", completion=CompletionSpec("choice", DB_ACTIONS))
class Db(CommandletBase):
    """Expose safe operational controls for the active SQLite database."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse the database action and run it against the active store."""
        parser = self.parser()
        parser.add_argument("action", choices=DB_ACTIONS)
        parser.add_argument("--file")
        parser.add_argument("--encrypt", action="store_true")
        parser.add_argument("--force", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground("database management commands")
        context.audit_capability("db.manage")
        db_action_handlers()[parsed.action](context, parsed)
        return ()


def db_action_handlers() -> dict[str, DbActionHandler]:
    """Return database action handlers keyed by CLI action name."""
    return {
        "checkpoint": checkpoint_database,
        "decrypt": decrypt_database,
        "encrypt": encrypt_database,
        "new": create_database,
        "path": print_database_path,
        "rekey": rekey_database,
        "status": status_database,
        "vacuum": vacuum_database,
    }


def checkpoint_database(context: CommandContext, parsed: Namespace) -> None:
    """Checkpoint the active database."""
    del parsed
    context.maintenance_store("db checkpoint").checkpoint()
    context.output("checkpoint complete")


def decrypt_database(context: CommandContext, parsed: Namespace) -> None:
    """Decrypt the active database."""
    del parsed
    decrypt_active_database(context)
    context.output("database decrypted")


def encrypt_database(context: CommandContext, parsed: Namespace) -> None:
    """Encrypt the active database."""
    del parsed
    encrypt_active_database(context)
    context.output("database encrypted")


def create_database(context: CommandContext, parsed: Namespace) -> None:
    """Create and switch to a fresh database."""
    new_active_database(
        context,
        file=Path(parsed.file) if parsed.file else None,
        encrypt=parsed.encrypt,
        force=parsed.force,
    )
    context.output(f"created db={context.require_db().path}")


def print_database_path(context: CommandContext, parsed: Namespace) -> None:
    """Print the active database path."""
    del parsed
    context.output(context.maintenance_store("db path").path)


def rekey_database(context: CommandContext, parsed: Namespace) -> None:
    """Rekey the active encrypted database."""
    del parsed
    rekey_active_database(context)
    context.output("database rekeyed")


def status_database(context: CommandContext, parsed: Namespace) -> None:
    """Print active database status."""
    del parsed
    print_database_status(context)


def vacuum_database(context: CommandContext, parsed: Namespace) -> None:
    """Vacuum the active database."""
    del parsed
    context.maintenance_store("db vacuum").vacuum()
    context.output("vacuum complete")


def print_database_status(context: CommandContext) -> None:
    """Print a concise status summary for the active database."""
    db = context.require_db()
    counts = db.table_counts()
    mode = "encrypted" if db.encrypted else "plaintext"
    context.output(f"path={db.path}")
    context.output(f"mode={mode}")
    context.output(f"events={counts['events']}")
    context.output(f"jobs={counts['jobs']}")


def encrypt_active_database(context: CommandContext) -> None:
    """Convert the active plaintext database file to SQLCipher encryption."""
    db = context.require_db()
    require_foreground_conversion(context, "db encrypt")
    if db.encrypted:
        raise ValueError("active database is already encrypted")
    passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    temp_path = temporary_database_path(db.path, "encrypt")
    db.checkpoint()
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


def database_related_paths(path: Path) -> list[Path]:
    """Return existing main/WAL/shared-memory files for a database path."""
    paths = [path, Path(f"{path}-wal"), Path(f"{path}-shm")]
    return [candidate for candidate in paths if candidate.exists()]


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
        replacer(db)
    context.db = db


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Db()
