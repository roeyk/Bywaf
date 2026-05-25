"""Database backend abstractions for event-store persistence.

Provides connection protocols and the default SQLite/SQLCipher backend used by
EventStore.

Used by:
- db.EventStore: delegates connection setup and schema initialization.
- future storage backends: provide the same connection contract without making
  callers import sqlite3 directly."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from .schema import SCHEMA, ensure_event_columns
from .support import set_sqlcipher_key, sqlcipher


class DatabaseCursor(Protocol):
    """Minimal cursor API used by EventStore mixins."""

    lastrowid: int | None
    rowcount: int

    def fetchone(self) -> Any | None:
        """Return the next row from the result set."""
        ...

    def fetchall(self) -> list[Any]:
        """Return all remaining rows from the result set."""
        ...


class DatabaseConnection(Protocol):
    """Minimal DB-API connection surface used by the store layer."""

    def execute(self, sql: str, parameters: Any = ...) -> DatabaseCursor:
        """Execute one statement and return a cursor-like object."""
        ...

    def executescript(self, sql_script: str) -> Any:
        """Execute a schema or migration script."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


class DatabaseBackend(Protocol):
    """Backend responsible for opening configured database connections."""

    path: Path
    passphrase: str | None

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Open one configured database connection."""
        ...

    def initialize(self) -> None:
        """Create or migrate the backing store."""
        ...


class SQLiteBackend:
    """SQLite/SQLCipher implementation of the database backend contract."""

    def __init__(self, path: Path | str, *, passphrase: str | None = None) -> None:
        self.path = Path(path)
        self.passphrase = passphrase

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Open a short-lived SQLite or SQLCipher connection.

        Each call returns a new DB-API connection so background jobs in separate
        processes can write through their own handles while SQLite WAL handles
        coordination.
        """
        driver: Any = sqlite3
        if self.passphrase is not None:
            if sqlcipher is None:
                raise RuntimeError("encrypted databases require the sqlcipher3-binary package")
            driver = sqlcipher
        conn = driver.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = driver.Row
        if self.passphrase is not None:
            set_sqlcipher_key(conn, self.passphrase)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the SQLite schema and apply compatibility migrations."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            ensure_event_columns(conn)


__all__ = [
    "DatabaseBackend",
    "DatabaseConnection",
    "DatabaseCursor",
    "SQLiteBackend",
]
