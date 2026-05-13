"""Active database management commandlet."""

from __future__ import annotations

import argparse
import getpass
import os
from collections.abc import Iterable
from pathlib import Path

from bywaf.db import EventStore, export_encrypted_database, export_plaintext_database
from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, Commandlet, CompletionSpec

DB_ACTIONS = ("checkpoint", "decrypt", "encrypt", "path", "rekey", "status", "vacuum")


class Db:
    """Expose safe operational controls for the active SQLite database."""

    spec = CommandSpec(
        name="db",
        description="Manage the active Bywaf SQLite database.",
        usage="db <status|path|checkpoint|vacuum|encrypt|decrypt|rekey>",
        examples=("db status", "db checkpoint", "db encrypt", "db rekey"),
        arguments=(
            ArgumentSpec(
                "action",
                "database operation",
                completion=CompletionSpec("choice", DB_ACTIONS),
            ),
        ),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse the database action and run it against the active store."""
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("action", choices=DB_ACTIONS)
        parsed = parser.parse_args(args)
        if context.db is None:
            raise ValueError("db command requires an active database")
        match parsed.action:
            case "checkpoint":
                context.db.checkpoint()
                print("checkpoint complete")
            case "decrypt":
                decrypt_active_database(context)
                print("database decrypted")
            case "encrypt":
                encrypt_active_database(context)
                print("database encrypted")
            case "path":
                print(context.db.path)
            case "rekey":
                rekey_active_database(context)
                print("database rekeyed")
            case "status":
                print_database_status(context)
            case "vacuum":
                context.db.vacuum()
                print("vacuum complete")
        return ()


def print_database_status(context: CommandContext) -> None:
    """Print a concise status summary for the active database."""
    if context.db is None:
        raise ValueError("db command requires an active database")
    counts = context.db.table_counts()
    mode = "encrypted" if context.db.encrypted else "plaintext"
    print(f"path={context.db.path}")
    print(f"mode={mode}")
    print(f"events={counts['events']}")
    print(f"jobs={counts['jobs']}")


def encrypt_active_database(context: CommandContext) -> None:
    """Convert the active plaintext database file to SQLCipher encryption."""
    if context.db is None:
        raise ValueError("db command requires an active database")
    require_foreground_conversion(context, "db encrypt")
    if context.db.encrypted:
        raise ValueError("active database is already encrypted")
    passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    temp_path = temporary_database_path(context.db.path, "encrypt")
    context.db.checkpoint()
    export_encrypted_database(context.db.path, temp_path, passphrase)
    EventStore(temp_path, passphrase=passphrase).table_counts()
    replace_database_file(context.db.path, temp_path)
    replace_active_store(context, EventStore(context.db.path, passphrase=passphrase))


def decrypt_active_database(context: CommandContext) -> None:
    """Convert the active encrypted database file to plaintext SQLite."""
    if context.db is None:
        raise ValueError("db command requires an active database")
    require_foreground_conversion(context, "db decrypt")
    if not context.db.encrypted or context.db.passphrase is None:
        raise ValueError("active database is already plaintext")
    confirmation = input("Decrypt active database and remove at-rest protection? type YES: ")
    if confirmation != "YES":
        raise ValueError("decryption cancelled")
    temp_path = temporary_database_path(context.db.path, "decrypt")
    context.db.checkpoint()
    export_plaintext_database(context.db.path, temp_path, source_passphrase=context.db.passphrase)
    EventStore(temp_path).table_counts()
    replace_database_file(context.db.path, temp_path)
    replace_active_store(context, EventStore(context.db.path))


def rekey_active_database(context: CommandContext) -> None:
    """Change the passphrase for the active encrypted database."""
    if context.db is None:
        raise ValueError("db command requires an active database")
    require_foreground_conversion(context, "db rekey")
    if not context.db.encrypted:
        raise ValueError("db rekey requires an encrypted database")
    passphrase = prompt_new_passphrase("New database passphrase: ", "Confirm database passphrase: ")
    context.db.rekey(passphrase)
    replace_active_store(context, EventStore(context.db.path, passphrase=passphrase))


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
    if context.metadata.get("background"):
        raise ValueError(f"{command} must run in the foreground")


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
