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

from bywaf.artifacts import ArtifactStore, artifact_db_path
from bywaf.config import Settings
from bywaf.db import EventStore, database_appears_encrypted, export_encrypted_database, export_plaintext_database
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.utils import complete_path

DB_ACTIONS = ("checkpoint", "decrypt", "encrypt", "export", "load", "new", "path", "rekey", "stats", "status", "vacuum")
DB_VIEW_ACTIONS = {"path", "stats", "status"}
ENCRYPTION_VAR = "encryption"
DbActionHandler = Callable[[CommandContext, Namespace], None]


@commandlet(
    name="db",
    description="Manage the active Bywaf SQLite database.",
    usage="db <status|stats|path|checkpoint|vacuum|new|load|export|encrypt|decrypt|rekey>",
    examples=("db status", "db stats", "db load file=client.sqlite3 --force", "db export file=snapshot.sqlite3", "db rekey"),
    capabilities=("db.manage", "db.raw", "filesystem.read", "filesystem.write", "framework.console.output"),
    database_actions=("view", "manage"),
)
@argument("action", "database operation", completion=CompletionSpec("choice", DB_ACTIONS))
class Db(CommandletBase):
    """Expose safe operational controls for the active SQLite database."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify read-only DB inspection separately from DB management."""
        action = args[0] if args else ""
        return ("view",) if action in DB_VIEW_ACTIONS else ("manage",)

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
        parsed = parser.parse_args(normalize_db_args(args))
        # DB management can replace the active store object. Keep it foreground
        # so the parent REPL/API process observes that replacement.
        if parsed.action not in DB_VIEW_ACTIONS:
            context.require_foreground("database management commands")
            context.audit_capability("db.manage")
        db_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete DB actions and file selectors."""
        del context
        if not args:
            return list(DB_ACTIONS)
        if len(args) == 1 and args[0] not in DB_ACTIONS:
            return [action for action in DB_ACTIONS if action.startswith(prefix)]
        if args[0] in {"export", "load", "new"}:
            if prefix.startswith("file="):
                return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
            return [candidate for candidate in ("file=", "--encrypt", "--force") if candidate.startswith(prefix)]
        return []


def db_action_handlers() -> dict[str, DbActionHandler]:
    """Return database action handlers keyed by CLI action name."""
    return {
        "checkpoint": checkpoint_database,
        "decrypt": decrypt_database,
        "encrypt": encrypt_database,
        "export": export_database,
        "load": load_database,
        "new": create_database,
        "path": print_database_path,
        "rekey": rekey_database,
        "stats": stats_database,
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


def export_database(context: CommandContext, parsed: Namespace) -> None:
    """Export the active database to a snapshot file."""
    if not parsed.file:
        raise ValueError("usage: db export file=<path> [--encrypt]")
    db = context.require_db()
    output = Path(parsed.file).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Checkpoint first so a copied/exported SQLite file includes WAL contents.
    db.checkpoint()
    if parsed.encrypt:
        passphrase = prompt_new_passphrase("New database export passphrase: ", "Confirm database export passphrase: ")
        export_encrypted_database(db.path, output, passphrase, source_passphrase=db.passphrase)
    elif db.encrypted:
        if db.passphrase is None:
            raise RuntimeError("encrypted database is missing its in-memory passphrase")
        export_plaintext_database(db.path, output, source_passphrase=db.passphrase)
    else:
        copy_plain_database(db.path, output)
    context.output(f"exported db={output}")


def load_database(context: CommandContext, parsed: Namespace) -> None:
    """Switch the active database to another file."""
    if not parsed.file:
        raise ValueError("usage: db load file=<path> [--force]")
    current = context.require_db()
    path = Path(parsed.file).expanduser()
    if not path.exists():
        raise ValueError(f"database does not exist: {path}")
    if is_same_path(path, current.path):
        raise ValueError("db load target is already the active database")
    if not parsed.force:
        response = input(f"Switch active database from {current.path} to {path}? [y/N]: ")
        if response.strip().lower() not in {"y", "yes"}:
            raise ValueError("db load cancelled")
    passphrase = None
    if database_appears_encrypted(path):
        passphrase = getpass.getpass(f"Passphrase for encrypted database {path}: ")
    new_db = EventStore(path, passphrase=passphrase)
    # On load, mark orphaned jobs before exposing the DB so status/report views
    # do not present stale background work as live.
    new_db.mark_stale_jobs()
    replace_active_store(context, new_db)
    context.output(f"loaded db={path}")


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


def stats_database(context: CommandContext, parsed: Namespace) -> None:
    """Print detailed active database statistics."""
    del parsed
    context.output(format_database_stats(context))


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


def format_database_stats(context: CommandContext) -> str:
    """Return a human-readable database statistics report."""
    db = context.require_db()
    mode = "encrypted" if db.encrypted else "plaintext"
    lines = [
        "Database statistics",
        f"  path: {db.path}",
        f"  mode: {mode}",
        "",
        "Main database files",
        *[f"  {path.name}: {format_bytes(path.stat().st_size)}" for path in database_related_paths(db.path)],
        "",
        "Main database tables",
        *format_count_rows(main_table_counts(db)),
        "",
        "Events by topic",
        *format_count_rows(event_topic_counts(db), empty="  none"),
        "",
        "Jobs by status",
        *format_count_rows(grouped_count(db, "jobs", "status"), empty="  none"),
        "",
        "Runtime entities",
        *format_count_rows(grouped_count(db, "runtime_entities", "entity_type"), empty="  none"),
        "",
        "Artifacts",
        *format_artifact_stats(db),
    ]
    return "\n".join(lines)


def main_table_counts(db: EventStore) -> list[tuple[str, int]]:
    """Return row counts for all non-internal main DB tables."""
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        counts = []
        for row in rows:
            name = str(row["name"] if hasattr(row, "keys") else row[0])
            count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()
            counts.append((name, int(count[0]) if count is not None else 0))
        return counts


def event_topic_counts(db: EventStore) -> list[tuple[str, int]]:
    """Return event counts grouped by topic."""
    with db.connect() as conn:
        rows = conn.execute("SELECT topic, COUNT(*) AS count FROM events GROUP BY topic ORDER BY count DESC, topic ASC").fetchall()
    return [(str(row["topic"]), int(row["count"])) for row in rows]


def grouped_count(db: EventStore, table: str, column: str) -> list[tuple[str, int]]:
    """Return grouped counts for trusted schema table/column names."""
    with db.connect() as conn:
        rows = conn.execute(
            f'SELECT "{column}" AS value, COUNT(*) AS count FROM "{table}" GROUP BY "{column}" ORDER BY count DESC, value ASC'
        ).fetchall()
    return [(str(row["value"] if row["value"] is not None else ""), int(row["count"])) for row in rows]


def format_artifact_stats(db: EventStore) -> list[str]:
    """Return artifact DB size and row-count lines."""
    path = artifact_db_path(db.path)
    related = database_related_paths(path)
    if not related:
        return [f"  path: {path}", "  files: none", "  artifacts: 0"]
    lines = [f"  path: {path}", "  files:"]
    lines.extend(f"    {file_path.name}: {format_bytes(file_path.stat().st_size)}" for file_path in related)
    store = ArtifactStore(path, passphrase=db.passphrase)
    with store.connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()
        size = conn.execute("SELECT COALESCE(SUM(size), 0) FROM artifacts").fetchone()
        content_types = conn.execute(
            "SELECT content_type, COUNT(*) AS count FROM artifacts GROUP BY content_type ORDER BY count DESC, content_type ASC"
        ).fetchall()
        commandlets = conn.execute(
            "SELECT commandlet, COUNT(*) AS count FROM artifacts GROUP BY commandlet ORDER BY count DESC, commandlet ASC"
        ).fetchall()
    lines.append(f"  artifacts: {int(total[0]) if total is not None else 0}")
    lines.append(f"  body bytes: {format_bytes(int(size[0]) if size is not None else 0)}")
    lines.append("  content types:")
    lines.extend(format_count_rows([(str(row["content_type"]), int(row["count"])) for row in content_types], indent="    ", empty="    none"))
    lines.append("  producing commandlets:")
    lines.extend(
        format_count_rows(
            [(str(row["commandlet"] or "(none)"), int(row["count"])) for row in commandlets],
            indent="    ",
            empty="    none",
        )
    )
    return lines


def format_count_rows(rows: list[tuple[str, int]], *, indent: str = "  ", empty: str = "  none") -> list[str]:
    """Format name/count rows with aligned counts."""
    if not rows:
        return [empty]
    width = max(len(name) for name, _count in rows)
    return [f"{indent}{name:<{width}}  {count}" for name, count in rows]


def format_bytes(size: int) -> str:
    """Return a compact byte-size string."""
    units = ("B", "KiB", "MiB", "GiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} {units[-1]}"


def normalize_db_args(args: list[str]) -> list[str]:
    """Accept selector-style `file=...` beside argparse-style `--file=...`."""
    normalized: list[str] = []
    for arg in args:
        if arg.startswith("file="):
            normalized.append(f"--file={arg.split('=', 1)[1]}")
        else:
            normalized.append(arg)
    return normalized


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
        # The REPL/API injects this callback so commandlets do not reach into
        # Runner internals directly.
        replacer(db)
    context.db = db


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Db()
