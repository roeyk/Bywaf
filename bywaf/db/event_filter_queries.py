"""Payload-filter event query helpers for EventStore.

These helpers answer runtime selector questions such as "which jobs produced
events matching host=...?" They are kept separate from direct event lookups
because they intentionally scan bounded event windows and then apply
schema-aware payload matching in Python.

Used by:
- `EventStoreEventQueryMixin`: inherits these methods for the public
  `EventStore` facade.
- runtime list/report selectors: filter already-loaded job, pipeline, and run
  rows by event payload criteria.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from .backends import DatabaseConnection
from ..event import Event
from ..event.filters import event_matches_payload_filters


class EventStorePayloadFilterQueryMixin:
    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        """Implemented by EventStore."""
        raise NotImplementedError

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
