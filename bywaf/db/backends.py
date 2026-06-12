"""Database backend abstractions for event-store persistence.

Provides connection protocols and the default SQLite/SQLCipher backend used by
EventStore.

Used by:
- db.EventStore: delegates connection setup and schema initialization.
- future storage backends: provide the same connection contract without making
  callers import sqlite3 directly."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .schema import SCHEMA, ensure_event_columns
from .support import set_sqlcipher_key, sqlcipher


@dataclass(frozen=True, slots=True)
class DatabaseBackendCapabilities:
    """Backend capabilities that affect storage behavior and operator docs.

    This represents what the active storage backend can safely promise.
    Constructed by: database backend implementations.
    Used by: EventStore, status output, and operator documentation paths.
    """

    name: str
    local_file: bool
    encrypted_at_rest: bool
    supports_backup: bool


class DatabaseCursor(Protocol):
    """Minimal cursor API used by EventStore mixins.

    Implemented by: sqlite/sqlcipher cursors and future backend adapters.
    Consumed by: event, job, trigger, maintenance, and runtime store mixins.
    """

    lastrowid: int | None
    rowcount: int

    def __iter__(self) -> Iterator[Any]:
        """Iterate over result rows, matching sqlite cursor behavior."""
        ...

    def fetchone(self) -> Any | None:
        """Return the next row from the result set."""
        ...

    def fetchall(self) -> list[Any]:
        """Return all remaining rows from the result set."""
        ...


class DatabaseConnection(Protocol):
    """Minimal DB-API connection surface used by the store layer.

    Implemented by: sqlite/sqlcipher connections and future backend adapters.
    Consumed by: `EventStore.connect()` callers through the store mixins.
    """

    def execute(self, sql: str, parameters: Any = ...) -> DatabaseCursor:
        """Execute one statement and return a cursor-like object."""
        ...

    def executemany(self, sql: str, parameters: Iterable[Any]) -> DatabaseCursor:
        """Execute one statement for multiple parameter rows."""
        ...

    def executescript(self, sql_script: str) -> Any:
        """Execute a schema or migration script."""
        ...

    def backup(self, target: Any) -> None:
        """Copy this database into another DB-API connection."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


class DatabaseBackend(Protocol):
    """Backend responsible for opening configured database connections.

    Implemented by: `SQLiteBackend` and future storage backends.
    Consumed by: `EventStore`, which delegates connection and initialization.
    """

    path: Path
    passphrase: str | None

    @property
    def capabilities(self) -> DatabaseBackendCapabilities:
        """Return backend traits that affect portability and operator behavior."""
        ...

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Open one configured database connection."""
        ...

    def initialize(self) -> None:
        """Create or migrate the backing store."""
        ...


class SQLiteBackend:
    """SQLite/SQLCipher implementation of the database backend contract.

    Constructed by: `EventStore` when no custom backend is supplied.
    Used by: local project databases and tests that exercise backend injection.
    """

    def __init__(self, path: Path | str, *, passphrase: str | None = None) -> None:
        # Keep only configuration here. Actual DB-API connections are opened
        # per operation by `connect()` so processes never share handles.
        self.path = Path(path)
        self.passphrase = passphrase

    @property
    def capabilities(self) -> DatabaseBackendCapabilities:
        """Return SQLite backend behavior relevant to portability."""
        return DatabaseBackendCapabilities(
            name="sqlite",
            local_file=True,
            encrypted_at_rest=self.passphrase is not None,
            supports_backup=True,
        )

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
            # SQLCipher requires the key before schema access or PRAGMA setup.
            set_sqlcipher_key(conn, self.passphrase)
        # WAL and busy_timeout are the default local-runtime compromise: they
        # let foreground commands and background jobs coordinate through SQLite
        # without long-lived shared connections.
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
            # Schema creation and compatibility migrations share the same
            # configured connection so encrypted databases are initialized with
            # the active passphrase.
            conn.executescript(SCHEMA)
            ensure_event_columns(conn)


__all__ = [
    "DatabaseBackend",
    "DatabaseBackendCapabilities",
    "DatabaseConnection",
    "DatabaseCursor",
    "SQLiteBackend",
]
