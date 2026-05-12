"""Event model used by commandlets and the SQLite bus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class Event:
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
        return cls(
            None,
            topic,
            payload,
            source,
            datetime.now(timezone.utc),
            pipeline_id,
            command_run_id,
            parent_command_run_id,
        )

    @classmethod
    def from_row(cls, row: Any) -> "Event":
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
        return json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
