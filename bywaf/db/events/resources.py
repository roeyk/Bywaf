"""Event-backed resource lookup helpers for EventStore.

Used by: `EventStoreEventMixin`, which exposes serial lookup, artifact counts,
and runtime display-name lookup through the public `EventStore` facade.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from ...event import Event
from ..backends import DatabaseConnection
from ..support import artifact_count_queries, resolve_serial_match


class EventStoreEventResourceMixin:
    """Resource lookup API derived from events.

    Used by: audit views, artifact summaries, serial lookup, and runtime views
    that need to resolve human-facing IDs from event columns and payload fields.
    """

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Implemented by EventStoreEventMixin."""
        raise NotImplementedError

    def events_for_serial(self, serial: str, *, limit: int = 1000) -> list[Event]:
        """Return events associated with a durable audit serial or unique prefix."""
        resolved = resolve_serial_match(serial, self.serials()) or serial
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                WHERE command_run_id = ?
                   OR pipeline_id = ?
                   OR json_extract(payload_json, '$.serial') = ?
                   OR json_extract(payload_json, '$.job_serial') = ?
                   OR json_extract(payload_json, '$.artifact_id') = ?
                   OR json_extract(payload_json, '$.target_id') = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (resolved, resolved, resolved, resolved, resolved, resolved, limit),
            )
            return [Event.from_row(row) for row in rows]

    def serials(self) -> list[str]:
        """Return known durable runtime/resource/artifact serial values."""
        values: set[str] = set()
        with self.connect() as conn:
            # Serials are scattered across first-class columns and JSON payloads
            # because jobs, artifacts, and framework requests are different
            # resource types. This query intentionally gathers all of them for
            # audit lookup and future cross-resource search.
            rows = conn.execute(
                """
                SELECT command_run_id AS serial FROM events WHERE command_run_id IS NOT NULL
                UNION
                SELECT pipeline_id AS serial FROM events WHERE pipeline_id IS NOT NULL
                UNION
                SELECT command_run_id AS serial FROM command_run_vars WHERE command_run_id IS NOT NULL
                UNION
                SELECT pipeline_id AS serial FROM command_run_vars WHERE pipeline_id IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.serial') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.serial') IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.job_serial') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.job_serial') IS NOT NULL
                UNION
                SELECT json_extract(payload_json, '$.artifact_id') AS serial
                FROM events
                WHERE json_extract(payload_json, '$.artifact_id') IS NOT NULL
                UNION
                SELECT serial FROM jobs WHERE serial IS NOT NULL
                """
            ).fetchall()
        for row in rows:
            if row["serial"] is not None:
                values.add(str(row["serial"]))
        return sorted(values)

    def artifact_counts_by_run(self) -> dict[str, int]:
        """Return artifact counts keyed by durable pipeline-step serial."""
        return self.artifact_counts("command_run_id")

    def artifact_counts_by_pipeline(self) -> dict[str, int]:
        """Return artifact counts keyed by durable pipeline serial."""
        return self.artifact_counts("pipeline_id")

    def artifact_counts_by_job(self) -> dict[str, int]:
        """Return artifact counts keyed by local job id string."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT json_extract(payload_json, '$.job_id') AS target_id,
                       COUNT(DISTINCT json_extract(payload_json, '$.artifact_id')) AS artifacts
                FROM events
                WHERE topic = 'artifact.attached'
                  AND json_extract(payload_json, '$.job_id') IS NOT NULL
                GROUP BY target_id
                """
            ).fetchall()
        return {str(row["target_id"]): int(row["artifacts"]) for row in rows}

    def artifact_counts(self, scope_column: str) -> dict[str, int]:
        """Return artifact counts grouped by a trusted events scope column."""
        try:
            sql = artifact_count_queries()[scope_column]
        except KeyError as exc:
            raise ValueError(f"unsupported artifact count scope: {scope_column}") from exc
        with self.connect() as conn:
            rows = conn.execute(sql).fetchall()
        return {str(row["target_id"]): int(row["artifacts"]) for row in rows}

    def runtime_names(self) -> dict[tuple[str, str], str]:
        """Return latest user-assigned names keyed by target type and id."""
        names: dict[tuple[str, str], str] = {}
        for event in self.events_matching(topic="runtime.name.assigned", limit=100000):
            target_type = event.payload.get("target_type")
            target_id = event.payload.get("target_id")
            name = event.payload.get("name")
            if target_type is not None and target_id is not None and name is not None:
                names[(str(target_type), str(target_id))] = str(name)
        return names


__all__ = ["EventStoreEventResourceMixin"]
