"""Public SQLite-backed event and runtime store facade.

Provides `EventStore` plus the stable database encryption/export helpers used by
Bywaf runtime, plugins, API, and resource tooling.

Used by:
- runner and plugin contexts: publish/read events and runtime state.
- REPL, completion, and API layers: inspect topics, jobs, runs, and pipelines.
- resource/export tooling: detect encryption and copy databases safely."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .events import EventStoreEventMixin
from .jobs import EventStoreJobMixin
from .maintenance import EventStoreMaintenanceMixin
from .runtime import EventStoreRuntimeMixin
from ..db_schema import SCHEMA, ensure_event_columns
from .secrets import EventStoreSecretMixin
from .support import (
    ACTIVE_JOB_STATUSES,
    SQLITE_HEADER,
    database_appears_encrypted,
    export_encrypted_database,
    export_plaintext_database,
    export_sqlcipher_database,
    new_serial,
    process_exists,
    set_sqlcipher_key,
    sql_literal,
    sqlcipher,
    sqlcipher_available,
)
from .triggers import EventStoreTriggerMixin
from ..subscriptions import Subscription


class EventStore(
    EventStoreMaintenanceMixin,
    EventStoreSecretMixin,
    EventStoreTriggerMixin,
    EventStoreEventMixin,
    EventStoreJobMixin,
    EventStoreRuntimeMixin,
):
    """SQLite implementation of Bywaf's event, runtime, and maintenance stores.

    Connections are intentionally short-lived. Each operation opens its own
    autocommit connection, which works well with multiprocessing and avoids
    sharing SQLite connection objects across process boundaries.
    """

    def __init__(self, path: Path | str, *, passphrase: str | None = None):
        self.path = Path(path)
        self.passphrase = passphrase
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a configured SQLite connection."""
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
        """Create the schema and apply lightweight compatibility migrations."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            ensure_event_columns(conn)


__all__ = [
    "ACTIVE_JOB_STATUSES",
    "EventStore",
    "SQLITE_HEADER",
    "Subscription",
    "database_appears_encrypted",
    "export_encrypted_database",
    "export_plaintext_database",
    "export_sqlcipher_database",
    "new_serial",
    "process_exists",
    "set_sqlcipher_key",
    "sql_literal",
    "sqlcipher",
    "sqlcipher_available",
]
