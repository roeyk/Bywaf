"""SQLite database path helpers for storage commandlets.

Used by:
- storage commandlets and operator workflows that create, inspect, or switch runtime databases.
- tests that verify database lifecycle behavior.
"""

from __future__ import annotations

from pathlib import Path


def database_related_paths(path: Path) -> list[Path]:
    """Return existing main/WAL/shared-memory files for a database path."""
    paths = [path, Path(f"{path}-wal"), Path(f"{path}-shm")]
    return [candidate for candidate in paths if candidate.exists()]
