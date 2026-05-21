"""Persistence helpers for REPL-managed resources.

Provides database load/save, config apply/load/save, history load/save, SQLite
backup behavior, and encrypted database passphrase prompts.

Used by:
- resource facade: implements `load/save db|config|history`.
- project switching and CLI startup: apply config and hydrate persistent state.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path

from ..db import EventStore, database_appears_encrypted, export_encrypted_database, export_plaintext_database
from ..runner import Runner
from ..toml_support import dump_variables_toml, load_data_file
from .state import ResourceState


def save_database(runner: Runner, path: Path, *, encrypt: bool = False) -> None:
    """Copy the active SQLite database to a snapshot file."""
    maintenance = runner.maintenance
    if encrypt:
        passphrase = prompt_database_passphrase(path, creating=True)
        export_encrypted_database(
            maintenance.path,
            path,
            passphrase,
            source_passphrase=maintenance.passphrase,
        )
    elif maintenance.encrypted:
        if maintenance.passphrase is None:
            raise RuntimeError("encrypted database is missing its in-memory passphrase")
        export_plaintext_database(maintenance.path, path, source_passphrase=maintenance.passphrase)
    else:
        copy_sqlite_database(maintenance.path, path)
    print(f"saved db={path}")


def load_database(runner: Runner, path: Path) -> None:
    """Switch the runner to a different SQLite database file."""
    passphrase = None
    if database_appears_encrypted(path):
        passphrase = prompt_database_passphrase(path, creating=False)
    runner.db = EventStore(path, passphrase=passphrase)
    runner.db.mark_stale_jobs()
    print(f"loaded db={path}")


def copy_sqlite_database(source: Path, destination: Path) -> None:
    """Use SQLite backup API instead of copying files around WAL state."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with EventStore(source).connect() as source_conn:
        with EventStore(destination).connect() as dest_conn:
            source_conn.backup(dest_conn)


def prompt_database_passphrase(path: Path, *, creating: bool) -> str:
    """Prompt for a database passphrase without ever storing it on disk."""
    action = "Create passphrase for encrypted database" if creating else "Passphrase for encrypted database"
    return getpass.getpass(f"{action} {path}: ")


def save_config(runner: Runner, path: Path) -> None:
    """Persist session variables as TOML or JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".toml":
        text = dump_variables_toml(runner.registry.varstore.values)
    else:
        text = json.dumps(runner.registry.varstore.values, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    print(f"saved config={path}")


def load_config(runner: Runner, path: Path) -> None:
    """Replace session variables from a TOML table or JSON object."""
    apply_config(runner, path)
    print(f"loaded config={path}")


def apply_config(runner: Runner, path: Path) -> None:
    """Replace session variables from config without user-facing output."""
    data = load_data_file(path)
    values = data.get("variables", data)
    if not isinstance(values, dict):
        raise ValueError(f"{path} variables must be an object/table")
    runner.registry.varstore.values.clear()
    for key, value in values.items():
        runner.registry.varstore.set(str(key), value)


def save_history(state: ResourceState, path: Path) -> None:
    """Save current-session history lines to a script-friendly file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(state.session_history)
    path.write_text(f"{text}\n" if text else "")
    print(f"saved history={path}")


def load_history(state: ResourceState, path: Path) -> None:
    """Load a history file as the current session history and append target."""
    state.history_path = path
    state.session_history = path.read_text().splitlines() if path.exists() else []
    print(f"loaded history={path}")
