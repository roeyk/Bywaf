"""Event publish/query operations for EventStore.

Provides event insertion, subscription fetch/poll, topic queries, audit serial
lookups, artifact event counts, and runtime naming lookup.

Used by:
- db.EventStore: inherits the event bus implementation.
- runner, plugins, REPL, API, and reporting code: publish and inspect events."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from .backends import DatabaseConnection
from .event_resources import EventStoreEventResourceMixin
from ..event import Event
from ..event.filters import event_matches_payload_filters
from ..subscriptions import Subscription


class EventStoreEventMixin(EventStoreEventResourceMixin):
    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
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

        # Events are also the source of truth for runtime object discovery.  As
        # soon as an event names a pipeline or step, ensure it has a stable
        # local ID for `pipelines`, `steps`, completion, and user selectors.
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
        """Poll until matching events arrive or the timeout expires.

        This is intentionally a small blocking loop over `fetch()`.  The event
        store stays SQLite-backed and process-safe without introducing a
        long-lived DB cursor or external notification service.
        """
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

    def events_after(
        self,
        after_id: int,
        *,
        topic: str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Return chronological events after an id within optional runtime scope."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                WHERE id > ?
                  AND (? IS NULL OR topic = ?)
                  AND (? IS NULL OR pipeline_id = ?)
                  AND (? IS NULL OR command_run_id = ?)
                  AND (? IS NULL OR parent_command_run_id = ?)
                ORDER BY id ASC
                LIMIT ?
                """,
                (
                    after_id,
                    topic,
                    topic,
                    pipeline_id,
                    pipeline_id,
                    command_run_id,
                    command_run_id,
                    parent_command_run_id,
                    parent_command_run_id,
                    limit,
                ),
            )
            return [Event.from_row(row) for row in rows]

    def event_by_id(self, event_id: int) -> Event | None:
        """Return one event by durable id."""
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return Event.from_row(row) if row is not None else None

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
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            return int(row[0]) if row is not None else 0

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

    def events_for_job(self, job_id: int, *, after_id: int = 0, limit: int = 1000) -> list[Event]:
        """Return events associated with a job id through scope or payload.

        Some events inherit job identity through command-run variable snapshots;
        framework events may instead store `job_id` in their payload.  Reporting
        and job inspection need both forms to reconstruct a full job timeline.
        """
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT events.*
                FROM events
                LEFT JOIN command_run_vars
                  ON command_run_vars.command_run_id = events.command_run_id
                  OR command_run_vars.pipeline_id = events.pipeline_id
                WHERE events.id > ?
                  AND (
                    command_run_vars.job_id = ?
                    OR json_extract(events.payload_json, '$.job_id') = ?
                  )
                ORDER BY events.id ASC
                LIMIT ?
                """,
                (after_id, job_id, job_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def events_for_job_topic(
        self,
        job_id: int,
        topic: str,
        *,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events for one job narrowed to one topic.

        Detail views often need only one operational topic, such as artifact
        attachments or recorded command arguments.  Keep those paths indexed and
        avoid broad job-timeline joins on larger project databases.
        """
        return self.events_for_job_topics(job_id, (topic,), after_id=after_id, limit=limit)

    def events_for_job_topics(
        self,
        job_id: int,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events for one job narrowed to a set of topics."""
        if not topics:
            return []
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT events.*
                FROM events
                WHERE events.id > ?
                  AND events.topic IN (SELECT value FROM json_each(?))
                  AND (
                    events.command_run_id IN (
                      SELECT command_run_id
                      FROM command_run_vars
                      WHERE job_id = ?
                    )
                    OR events.pipeline_id IN (
                      SELECT pipeline_id
                      FROM command_run_vars
                      WHERE job_id = ?
                    )
                    OR json_extract(events.payload_json, '$.job_id') = ?
                  )
                ORDER BY events.id ASC
                LIMIT ?
                """,
                (after_id, json.dumps(topics), job_id, job_id, job_id, limit),
            )
            return [Event.from_row(row) for row in rows]

    def job_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[int]:
        """Return job ids whose associated events match payload filters.

        Runtime list filters need to answer "which jobs produced events matching
        host=...?" Doing that by querying every job separately scales poorly on
        real project databases, so this scans the event/job association once
        and then lets the caller filter its already-loaded job rows by id.
        """
        if not filters:
            return set()
        matched: set[int] = set()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT command_run_vars.job_id AS matched_job_id,
                                events.*
                FROM events
                JOIN command_run_vars
                  ON command_run_vars.command_run_id = events.command_run_id
                  OR command_run_vars.pipeline_id = events.pipeline_id
                WHERE command_run_vars.job_id IS NOT NULL
                ORDER BY events.id DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in rows:
                if event_matches_payload_filters(Event.from_row(row), filters):
                    matched.add(int(row["matched_job_id"]))
            payload_rows = conn.execute(
                """
                SELECT json_extract(payload_json, '$.job_id') AS matched_job_id,
                       events.*
                FROM events
                WHERE json_extract(payload_json, '$.job_id') IS NOT NULL
                ORDER BY events.id DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in payload_rows:
                if event_matches_payload_filters(Event.from_row(row), filters):
                    matched.add(int(row["matched_job_id"]))
        return matched

    def pipeline_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[str]:
        """Return pipeline serials whose events match payload filters."""
        if not filters:
            return set()
        matched: set[str] = set()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                WHERE pipeline_id IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in rows:
                event = Event.from_row(row)
                if event.pipeline_id and event_matches_payload_filters(event, filters):
                    matched.add(event.pipeline_id)
        return matched

    def run_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[str]:
        """Return command-run serials whose events match payload filters."""
        if not filters:
            return set()
        matched: set[str] = set()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                WHERE command_run_id IS NOT NULL
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in rows:
                event = Event.from_row(row)
                if event.command_run_id and event_matches_payload_filters(event, filters):
                    matched.add(event.command_run_id)
        return matched
