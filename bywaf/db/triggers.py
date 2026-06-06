"""Trigger cursor and lifecycle state operations for EventStore.

Provides persisted trigger high-water marks and enabled/fired state rows.

Used by:
- db.EventStore: inherits trigger state persistence.
- trigger runtime: resumes rules without replaying already-handled events."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from .backends import DatabaseConnection

class EventStoreTriggerMixin:
    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def trigger_cursor(self, name: str) -> int:
        """Return the persisted high-water mark for one trigger."""
        with self.connect() as conn:
            row = conn.execute("SELECT last_event_id FROM trigger_state WHERE name = ?", (name,)).fetchone()
        return int(row["last_event_id"]) if row is not None else 0

    def update_trigger_state(
        self,
        name: str,
        *,
        enabled: bool,
        last_event_id: int | None = None,
        last_fired_event_id: int | None = None,
    ) -> None:
        """Persist trigger lifecycle/cursor state."""
        now = datetime.now(timezone.utc).isoformat()
        next_last = self.trigger_cursor(name) if last_event_id is None else last_event_id
        with self.connect() as conn:
            # last_event_id is the replay cursor. last_fired_event_id is only a
            # diagnostic pointer to the event that most recently matched.
            conn.execute(
                """
                INSERT INTO trigger_state(name, enabled, last_event_id, last_fired_event_id, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    enabled = excluded.enabled,
                    last_event_id = excluded.last_event_id,
                    last_fired_event_id = COALESCE(excluded.last_fired_event_id, trigger_state.last_fired_event_id),
                    updated_at = excluded.updated_at
                """,
                (name, 1 if enabled else 0, next_last, last_fired_event_id, now),
            )

    def trigger_states(self) -> list[Any]:
        """Return persisted trigger state rows."""
        with self.connect() as conn:
            return list(conn.execute("SELECT * FROM trigger_state ORDER BY name"))
