"""Event value objects shared across stores and commandlets.

Provides the Event dataclass used to move structured event records through the
runner, plugins, REPL display, and tests.

Used by:
- EventStore and runner: represent persisted rows as Python objects.
- plugins and tests: assert topics, payloads, and serial identifiers."""


from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..time_format import bywaf_now


@dataclass(frozen=True, slots=True)
class Event:
    """One immutable message on the SQLite event bus."""

    id: int | None
    topic: str
    payload: dict[str, Any]
    source: str
    created_at: datetime
    pipeline_id: str | None = None
    command_run_id: str | None = None
    parent_command_run_id: str | None = None

    @classmethod
    def new(
        cls,
        topic: str,
        payload: dict[str, Any],
        source: str,
        *,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> "Event":
        """Create a new unsaved event with an operator-local timestamp."""
        return cls(
            None,
            topic,
            payload,
            source,
            bywaf_now(),
            pipeline_id,
            command_run_id,
            parent_command_run_id,
        )

    @classmethod
    def from_row(cls, row: Any) -> "Event":
        """Rehydrate an Event from a sqlite3.Row."""
        # Older DB rows/tests may not have newer provenance columns, so check
        # row.keys() instead of assuming every schema-era field exists.
        return cls(
            id=row["id"],
            topic=row["topic"],
            payload=json.loads(row["payload_json"]),
            source=row["source"],
            created_at=datetime.fromisoformat(row["created_at"]),
            pipeline_id=row["pipeline_id"] if "pipeline_id" in row.keys() else None,
            command_run_id=row["command_run_id"] if "command_run_id" in row.keys() else None,
            parent_command_run_id=(
                row["parent_command_run_id"] if "parent_command_run_id" in row.keys() else None
            ),
        )

    def payload_json(self) -> str:
        """Serialize payloads deterministically for storage and tests."""
        # Stable key ordering keeps event comparisons and signed/exported
        # payloads predictable.
        return json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
