"""Maintenance operations for EventStore.

Provides checkpoint, vacuum, rekey, encryption-state, and table-count helpers.

Used by:
- db.EventStore: inherits these operations for storage maintenance.
- storage/runtime plugins: expose maintenance commands to users."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .backends import DatabaseConnection
from .support import sql_literal


class EventStoreMaintenanceMixin:
    """Adds maintenance and encryption-state methods to `EventStore`.

    Constructed by: multiple inheritance in `db.EventStore`.
    Used by: database status, checkpoint, vacuum, and rekey command paths.
    """

    path: Path

    @property
    def passphrase(self) -> str | None:
        """Implemented by EventStore."""
        raise NotImplementedError

    @passphrase.setter
    def passphrase(self, value: str | None) -> None:
        """Implemented by EventStore."""
        raise NotImplementedError

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def checkpoint(self) -> None:
        """Fold WAL contents into the main DB file during clean shutdown."""
        with self.connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def vacuum(self) -> None:
        """Rebuild the active database to reclaim free pages."""
        with self.connect() as conn:
            conn.execute("VACUUM")

    def rekey(self, new_passphrase: str) -> None:
        """Change the SQLCipher passphrase for the active encrypted database."""
        if self.passphrase is None:
            raise ValueError("db rekey requires an encrypted database")
        with self.connect() as conn:
            conn.execute(f"PRAGMA rekey = {sql_literal(new_passphrase)}")
        old_passphrase = self.passphrase
        self.passphrase = new_passphrase
        try:
            # Force a read with the new key before accepting the in-memory
            # passphrase change. If SQLCipher rejects the key, restore state.
            self.table_counts()
        except Exception:
            self.passphrase = old_passphrase
            raise

    @property
    def encrypted(self) -> bool:
        """Return whether this store uses a SQLCipher passphrase."""
        return self.passphrase is not None

    def table_counts(self) -> dict[str, int]:
        """Return row counts for core tables used by `db status`."""
        with self.connect() as conn:
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            jobs = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()
            return {
                "events": int(events[0]) if events is not None else 0,
                "jobs": int(jobs[0]) if jobs is not None else 0,
            }
