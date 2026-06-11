"""Event store protocol for persistence abstractions.

Used by: command contexts, runner code, runtime views, and tests that need an
event/audit store without depending on the concrete SQLite implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..event import Event
from ..subscriptions import Subscription


@runtime_checkable
class EventStoreProtocol(Protocol):
    """Append-only event bus and audit-log storage."""

    path: Path

    @property
    def passphrase(self) -> str | None:
        """Return the in-memory DB passphrase, when one is active."""
        ...

    @passphrase.setter
    def passphrase(self, value: str | None) -> None:
        """Replace the active DB passphrase after a rekey."""
        ...

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
        """Persist one event and return it with its durable id."""
        ...

    def fetch(self, subscription: Subscription) -> list[Event]:
        """Return events matching a scoped subscription."""
        ...

    def poll(
        self,
        subscription: Subscription,
        *,
        timeout_seconds: float = 0,
        interval_seconds: float = 0.25,
    ) -> list[Event]:
        """Poll the event store until matching events arrive or timeout."""
        ...

    def events_matching(
        self,
        *,
        topic: str | None = None,
        command_run_id: str | None = None,
        pipeline_id: str | None = None,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events filtered by topic and runtime scope."""
        ...

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
        ...

    def events_for_topic(self, topic: str, limit: int = 100) -> list[Event]:
        """Return events for one topic."""
        ...

    def event_by_id(self, event_id: int) -> Event | None:
        """Return one event by durable id."""
        ...

    def recent_events(self, limit: int = 25) -> list[Event]:
        """Return the latest events in chronological order."""
        ...

    def latest_event_id(self) -> int:
        """Return the highest event id currently stored."""
        ...

    def topics(self) -> list[str]:
        """Return known event topics."""
        ...

    def events_for_job(self, job_id: int, *, after_id: int = 0, limit: int = 1000) -> list[Event]:
        """Return events associated with one local job id."""
        ...

    def events_for_job_topic(
        self,
        job_id: int,
        topic: str,
        *,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events associated with one local job id and topic."""
        ...

    def events_for_job_topics(
        self,
        job_id: int,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events associated with one local job id and topics."""
        ...

    def job_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[int]:
        """Return job ids with at least one associated event matching filters."""
        ...

    def pipeline_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[str]:
        """Return pipeline serials with at least one matching event."""
        ...

    def run_ids_matching_payload_filters(self, filters: dict[str, str], *, limit: int = 100000) -> set[str]:
        """Return command-run serials with at least one matching event."""
        ...

    def events_for_serial(self, serial: str, *, limit: int = 1000) -> list[Event]:
        """Return events associated with one durable serial."""
        ...

    def serials(self) -> list[str]:
        """Return durable serial values known to the event store."""
        ...
