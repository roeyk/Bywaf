"""Event publish/query operations for EventStore.

Provides event insertion, subscription fetch/poll, topic queries, audit serial
lookups, artifact event counts, and runtime naming lookup.

Used by:
- db.EventStore: inherits the event bus implementation.
- runner, plugins, REPL, API, and reporting code: publish and inspect events."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from .support import artifact_count_queries
from ..events import Event
from ..subscriptions import Subscription


class EventStoreEventMixin:
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Implemented by EventStore."""
        raise NotImplementedError

    def publish(
        self,
        topic: str,
        payload: dict[str, Any],
        source: str,
        *,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> Event:
        """Insert one event and return it with its SQLite id populated."""
        event = Event.new(
            topic,
            payload,
            source,
            pipeline_id=pipeline_id,
            command_run_id=command_run_id,
            parent_command_run_id=parent_command_run_id,
        )
        saved: Event
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events(
                    topic,
                    payload_json,
                    source,
                    created_at,
                    pipeline_id,
                    command_run_id,
                    parent_command_run_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.topic,
                    event.payload_json(),
                    event.source,
                    event.created_at.isoformat(),
                    event.pipeline_id,
                    event.command_run_id,
                    event.parent_command_run_id,
                ),
            )
            saved = Event(
                cursor.lastrowid,
                event.topic,
                event.payload,
                event.source,
                event.created_at,
                event.pipeline_id,
                event.command_run_id,
                event.parent_command_run_id,
            )
        runtime_store = cast(Any, self)
        if saved.pipeline_id:
            runtime_store.ensure_runtime_entity("pipeline", saved.pipeline_id, saved.created_at.isoformat())
        if saved.command_run_id:
            runtime_store.ensure_runtime_entity("run", saved.command_run_id, saved.created_at.isoformat())
        return saved

    def fetch(self, subscription: Subscription) -> list[Event]:
        """Return events matching a subscription.

        The topic list is passed as a JSON array and expanded with SQLite's
        `json_each` table-valued function. That keeps the SQL text fixed while
        still supporting a variable number of topics, which avoids both SQL
        injection risk and Bandit false positives.
        """
        if not subscription.topics:
            return []
        sql = """
            SELECT * FROM events
            WHERE id > ?
              AND topic IN (SELECT value FROM json_each(?))
              AND (? IS NULL OR pipeline_id = ?)
              AND (? IS NULL OR command_run_id = ?)
              AND (? IS NULL OR parent_command_run_id = ?)
            ORDER BY id ASC
            LIMIT ?
        """
        params: list[Any] = [
            subscription.after_id,
            json.dumps(subscription.topics),
            subscription.pipeline_id,
            subscription.pipeline_id,
            subscription.command_run_id,
            subscription.command_run_id,
            subscription.parent_command_run_id,
            subscription.parent_command_run_id,
            subscription.limit,
        ]
        with self.connect() as conn:
            return [Event.from_row(row) for row in conn.execute(sql, tuple(params))]

    def poll(
        self,
        subscription: Subscription,
        *,
        timeout_seconds: float = 0,
        interval_seconds: float = 0.25,
    ) -> list[Event]:
        """Poll until matching events arrive or the timeout expires."""
        deadline = time.monotonic() + timeout_seconds
        while True:
            events = self.fetch(subscription)
            if events or timeout_seconds <= 0 or time.monotonic() >= deadline:
                return events
            time.sleep(interval_seconds)
    def topics(self) -> list[str]:
        """Return distinct event topics currently present in the database."""
        with self.connect() as conn:
            rows = conn.execute("SELECT DISTINCT topic FROM events ORDER BY topic")
            return [row["topic"] for row in rows]

    def events_for_topic(self, topic: str, limit: int = 100) -> list[Event]:
        """Return recent events for one topic."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE topic = ? ORDER BY id ASC LIMIT ?",
                (topic, limit),
            )
            return [Event.from_row(row) for row in rows]

    def recent_events(self, limit: int = 25) -> list[Event]:
        """Return the latest events as a chronological slice."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM (
                    SELECT * FROM events ORDER BY id DESC LIMIT ?
                )
                ORDER BY id ASC
                """,
                (limit,),
            )
            return [Event.from_row(row) for row in rows]

    def latest_event_id(self) -> int:
        """Return the current highest event id, or zero for an empty DB."""
        with self.connect() as conn:
            return int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events filtered by optional topic/run/pipeline scope.

        Optional predicates are expressed as fixed nullable SQL predicates so no
        SQL text is assembled from user-controlled values.
        """
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE id > ?
                  AND (? IS NULL OR topic = ?)
                  AND (? IS NULL OR command_run_id = ?)
                  AND (? IS NULL OR pipeline_id = ?)
                ORDER BY id ASC
                LIMIT ?
                """,
                (after_id, topic, topic, command_run_id, command_run_id, pipeline_id, pipeline_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_for_job(self, job_id: int, *, limit: int = 1000) -> list[Event]:
        """Return events associated with a job id through scope or payload."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT events.*
                FROM events
                LEFT JOIN command_run_vars
                  ON command_run_vars.command_run_id = events.command_run_id
                  OR command_run_vars.pipeline_id = events.pipeline_id
                WHERE command_run_vars.job_id = ?
                   OR json_extract(events.payload_json, '$.job_id') = ?
                ORDER BY events.id ASC
                LIMIT ?
                """,
                (job_id, job_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_for_serial(self, serial: str, *, limit: int = 1000) -> list[Event]:
        """Return events associated with a globally unique audit serial."""
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
                (serial, serial, serial, serial, serial, serial, limit),
            )
            return [Event.from_row(row) for row in rows]

    def serials(self) -> list[str]:
        """Return known durable runtime/resource/artifact serial values."""
        values: set[str] = set()
        with self.connect() as conn:
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
        """Return artifact counts keyed by durable command-run serial."""
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
