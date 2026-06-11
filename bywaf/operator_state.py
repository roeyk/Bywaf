"""Operator-local state that should not be written to the project database.

Provides small JSON-backed cursors for UI features such as runtime `--new`
views. These cursors are local operator state, not audit evidence.

Used by:
- runtime view commandlets: remember the last seen job, pipeline, or step ID
  without emitting database events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Settings
from .projects import ProjectPaths

VIEW_CURSORS_FILE = "view-cursors.json"
ACTIVE_DATABASE_FILE = "active-database.json"


def operator_state_dir(runner: object | None) -> Path:
    """Return the directory for operator-local state."""
    project = getattr(runner, "project", None)
    if isinstance(project, ProjectPaths):
        return project.path
    db = getattr(runner, "db", None)
    db_path = getattr(db, "path", None)
    if isinstance(db_path, Path):
        return db_path.parent
    return Settings().state_dir


def view_cursors_path(runner: object | None) -> Path:
    """Return the path for runtime view cursors."""
    return operator_state_dir(runner) / VIEW_CURSORS_FILE


def active_database_path() -> Path:
    """Return the operator-local pointer for the last selected ad hoc DB."""
    return Settings().state_dir / ACTIVE_DATABASE_FILE


def load_active_database() -> Path | None:
    """Return the last selected ad hoc DB path, ignoring stale local state."""
    path = active_database_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("database"), str):
        return None
    database = Path(data["database"]).expanduser()
    return database if database.exists() else None


def save_active_database(database: Path) -> None:
    """Persist the ad hoc DB that normal startup should reopen next time."""
    path = active_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"database": str(database)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_view_cursors(runner: object | None) -> dict[str, int]:
    """Load runtime view cursors, ignoring malformed local state."""
    path = view_cursors_path(runner)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): int(value) for key, value in data.items() if isinstance(value, int) or str(value).isdigit()}


def view_cursor(runner: object | None, name: str) -> int:
    """Return the last seen local runtime ID for one view."""
    return load_view_cursors(runner).get(name, 0)


def update_view_cursor(runner: object | None, name: str, value: int) -> None:
    """Persist a runtime view cursor outside the project database."""
    path = view_cursors_path(runner)
    path.parent.mkdir(parents=True, exist_ok=True)
    cursors: dict[str, Any] = load_view_cursors(runner)
    cursors[name] = max(int(cursors.get(name, 0)), int(value))
    path.write_text(json.dumps(cursors, indent=2, sort_keys=True) + "\n", encoding="utf-8")
