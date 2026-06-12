"""Event publish/query package for EventStore.

Provides event insertion, subscription fetch/poll, topic queries, audit serial
lookups, artifact event counts, and runtime naming lookup.

Used by:
- db.EventStore: inherits the event bus implementation.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- runner, plugins, REPL, API, and reporting code: publish and inspect events."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from .queries import EventStoreEventQueryMixin
from .resources import EventStoreEventResourceMixin
from ...event import Event
from ...subscriptions import Subscription
from ..backends import DatabaseConnection


class EventStoreEventMixin(EventStoreEventQueryMixin, EventStoreEventResourceMixin):
    """Event publish/subscribe API mixed into `db.EventStore`.

    Constructed by: Python's MRO when `EventStore` inherits this mixin.
    Used by: runner/plugin/repl code through `EventStore.publish()`,
    `fetch()`, `poll()`, and the query/resource methods inherited below.
    """

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


__all__ = ["EventStoreEventMixin"]
