"""Public event and runtime store facade.

Provides `EventStore` plus stable database encryption/export helpers used by
Bywaf runtime, plugins, API, and resource tooling. SQLite remains the default
backend, but connection setup is isolated behind a backend interface.

Used by:
- runner and plugin contexts: publish/read events and runtime state.
- REPL, completion, and API layers: inspect topics, jobs, runs, and pipelines.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- resource/export tooling: detect encryption and copy databases safely."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .backends import DatabaseBackend, DatabaseBackendCapabilities, DatabaseConnection, SQLiteBackend
from .events import EventStoreEventMixin
from .jobs import EventStoreJobMixin
from .maintenance import EventStoreMaintenanceMixin
from .runtime import EventStoreRuntimeMixin
from .secrets import EventStoreSecretMixin
from .support import (
    ACTIVE_JOB_STATUSES,
    CROCKFORD_BASE32_ALPHABET,
    SERIAL_BODY_LENGTH,
    SERIAL_DISPLAY_LENGTH,
    SERIAL_RANDOM_BITS,
    SQLITE_HEADER,
    crockford_base32,
    database_appears_encrypted,
    export_encrypted_database,
    export_plaintext_database,
    export_sqlcipher_database,
    new_serial,
    normalize_serial_lookup,
    process_exists,
    resolve_serial_match,
    serial_body,
    serial_matches,
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
    """Default implementation of Bywaf's event and runtime stores.

    The default backend is SQLite. Connections remain intentionally
    short-lived, which works well with multiprocessing and avoids sharing DB
    connection objects across process boundaries.
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        passphrase: str | None = None,
        backend: DatabaseBackend | None = None,
    ):
        db_backend = backend
        if db_backend is None:
            if path is None:
                raise ValueError("EventStore requires either path= or backend=")
            db_backend = SQLiteBackend(path, passphrase=passphrase)
        self.backend = db_backend
        self.path = db_backend.path
        self.initialize()

    @property
    def passphrase(self) -> str | None:
        """Return the backend passphrase, when the backend supports one."""
        return self.backend.passphrase

    @passphrase.setter
    def passphrase(self, value: str | None) -> None:
        """Update the backend passphrase after operations such as rekey."""
        self.backend.passphrase = value

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Open a fresh configured connection from the active backend.

        Multiprocessing depends on this being a per-operation connection, not
        a cached object shared between foreground and background workers.
        """
        with self.backend.connect() as conn:
            yield conn

    def initialize(self) -> None:
        """Initialize the active backend."""
        self.backend.initialize()


# Public database facade.  Most callers should import `EventStore` and database
# export/encryption helpers from `bywaf.db`, not from the lower-level mixin
# modules that implement individual event, job, trigger, and maintenance APIs.
__all__ = [
    "ACTIVE_JOB_STATUSES",
    "DatabaseBackend",
    "DatabaseBackendCapabilities",
    "DatabaseConnection",
    "EventStore",
    "CROCKFORD_BASE32_ALPHABET",
    "SERIAL_BODY_LENGTH",
    "SERIAL_DISPLAY_LENGTH",
    "SERIAL_RANDOM_BITS",
    "SQLITE_HEADER",
    "SQLiteBackend",
    "Subscription",
    "crockford_base32",
    "database_appears_encrypted",
    "export_encrypted_database",
    "export_plaintext_database",
    "export_sqlcipher_database",
    "new_serial",
    "normalize_serial_lookup",
    "process_exists",
    "resolve_serial_match",
    "serial_body",
    "serial_matches",
    "set_sqlcipher_key",
    "sql_literal",
    "sqlcipher",
    "sqlcipher_available",
]
