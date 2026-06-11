"""Event lookup operations for EventStore.

Used by: `db.events.EventStoreEventMixin`, which exposes these methods through
the public `EventStore` facade. Keeping read-heavy query helpers here lets the
event publish/poll mixin stay focused on insertion and subscriptions.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager

from .filter_queries import PayloadFilterMixin
from ...event import Event
from ..backends import DatabaseConnection


class EventStoreEventQueryMixin(PayloadFilterMixin):
    """Topic, id, job, and scope query API mixed into `EventStore`.

    Used by: REPL `event`/`job` views, runner replay selection, reports,
    completion providers, and tests that inspect emitted facts.
    """

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

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


__all__ = ["EventStoreEventQueryMixin"]
