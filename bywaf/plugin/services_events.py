"""CommandContext event-bus service.

Provides `ContextEvents`, the plugin-facing API for publishing, fetching,
following, and validating framework events.

Used by:
- `CommandContext.events`: constructs this service for plugin code.
- bundled and external plugins: publish structured facts and query prior
  events without reaching into the raw database object.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..db import EventStore, Subscription
from ..event import Event
from ..event.schemas import EventSchemaObject, event_schema, schema_objects, validate_event_payload

if TYPE_CHECKING:
    from .context import CommandContext


@dataclass(frozen=True, slots=True)
class ContextEvents:
    """Capability-aware event API exposed to commandlets.

    This service is the normal plugin path for event bus access.  It attaches
    pipeline/step provenance automatically and audits topic-specific read/write
    capabilities without exposing the full database object.
    """

    context: CommandContext

    def publish(self, topic: str, payload: dict[str, Any]) -> Event:
        """Publish one event in the current commandlet scope."""
        db = self.require_event_store(f"{self.context.source} event publish")
        self.enforce_topic_contract(topic)
        self.validate_payload(topic, payload)
        self.context.audit_capability(f"db.write:{topic}")
        return db.publish(
            topic,
            payload,
            self.context.source,
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def enforce_topic_contract(self, topic: str) -> None:
        """Apply commandlet topic declaration and schema-registration policy."""
        declared = self.context.declared_emits
        if declared is not None and topic not in declared:
            self.handle_topic_policy(
                topic,
                mode=self.context.topic_contract_mode,
                reason="undeclared",
                message=f"{self.context.source} published undeclared topic: {topic}",
            )
        if event_schema(topic) is None:
            self.handle_topic_policy(
                topic,
                mode=self.context.unregistered_topic_mode,
                reason="unregistered",
                message=f"{self.context.source} published topic without a registered schema: {topic}",
            )

    def handle_topic_policy(self, topic: str, *, mode: str, reason: str, message: str) -> None:
        """Audit, warn, or reject one topic-contract policy event."""
        if mode == "off":
            return
        self.publish_topic_policy_event(topic, reason=reason, decision=mode, message=message)
        if mode == "enforce":
            raise PermissionError(message)

    def publish_topic_policy_event(self, topic: str, *, reason: str, decision: str, message: str) -> None:
        """Persist one deduplicated topic-contract policy decision."""
        db = self.require_event_store(f"{self.context.source} topic policy")
        audited = self.context.metadata.setdefault("_audited_topic_policy", set())
        audit_key = (self.context.source, self.context.command_run_id, topic, reason, decision)
        if audit_key in audited:
            return
        audited.add(audit_key)
        db.publish(
            "plugin.topic.policy",
            {
                "commandlet": self.context.source,
                "topic": topic,
                "reason": reason,
                "decision": decision,
                "message": message,
                "job_id": self.context.job_id,
                "pipeline_id": self.context.pipeline_id,
                "command_run_id": self.context.command_run_id,
                "parent_command_run_id": self.context.parent_command_run_id,
            },
            self.context.source,
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def validate_payload(self, topic: str, payload: Mapping[str, Any]) -> None:
        """Validate schema-backed plugin events before they enter the event log."""
        if self.context.schema_validation_mode == "off":
            return
        errors = validate_event_payload(topic, payload)
        if errors:
            detail = "; ".join(errors)
            raise ValueError(f"{self.context.source} published invalid {topic} event: {detail}")

    def publish_object(self, obj: EventSchemaObject) -> Event:
        """Publish one shared or plugin-owned schema object."""
        return self.publish(obj.schema_topic(), obj.to_payload())

    def objects(self, events: Iterable[Event], factory):
        """Deserialize matching events into schema objects."""
        return schema_objects(events, factory)

    def fetch(
        self,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 100,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> list[Event]:
        """Fetch events by topic with optional run/pipeline scoping."""
        db = self.require_event_store(f"{self.context.source} event fetch")
        for topic in topics:
            self.context.audit_capability(f"db.read:{topic}")
        return db.fetch(
            Subscription(
                topics=topics,
                after_id=after_id,
                limit=limit,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
                parent_command_run_id=parent_command_run_id,
            )
        )

    def follow(
        self,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 100,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
        until_parent_done: bool = False,
        idle_interval: float = 1.0,
        timeout: float | None = None,
    ) -> Iterable[Event]:
        """Yield matching events until cancellation, timeout, or parent completion."""
        cursor = after_id
        scoped_pipeline = pipeline_id if pipeline_id is not None else self.context.pipeline_id
        scoped_run = command_run_id
        if scoped_run is None and until_parent_done:
            scoped_run = self.context.parent_command_run_id
        deadline = None if timeout is None or timeout <= 0 else time.monotonic() + timeout
        while True:
            if self.context.cancelled():
                return
            # Fetch in bounded batches and advance the cursor only after events
            # are returned.  That lets long-running consumers stream new events
            # without holding a database cursor open.
            events = self.fetch(
                topics,
                after_id=cursor,
                limit=limit,
                pipeline_id=scoped_pipeline,
                command_run_id=scoped_run,
                parent_command_run_id=parent_command_run_id,
            )
            if events:
                cursor = max(event.id or cursor for event in events)
                yield from events
                continue
            if until_parent_done and self.command_run_terminal(scoped_run):
                return
            if deadline is not None and time.monotonic() >= deadline:
                return
            sleep_for = idle_interval
            if deadline is not None:
                sleep_for = min(sleep_for, max(0.0, deadline - time.monotonic()))
            time.sleep(max(0.0, sleep_for))

    def command_run_terminal(self, command_run_id: str | None) -> bool:
        """Return whether a pipeline step has reached a terminal lifecycle event."""
        if command_run_id is None:
            return False
        db = self.require_event_store(f"{self.context.source} event follow")
        # Parent-following consumers stop when the upstream step publishes a
        # terminal lifecycle event.  Check both success and failure so a
        # downstream listener does not wait forever after an upstream exception.
        self.context.audit_capability("db.read:command.run.completed")
        self.context.audit_capability("db.read:command.run.failed")
        return bool(
            db.events_matching(topic="command.run.completed", command_run_id=command_run_id, limit=1)
            or db.events_matching(topic="command.run.failed", command_run_id=command_run_id, limit=1)
        )

    def query(
        self,
        *,
        topic: str | None = None,
        step: str | None = None,
        pipeline: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        """Query events with optional topic, step, and pipeline filters."""
        db = self.require_event_store(f"{self.context.source} event query")
        self.context.audit_capability(f"db.read:{topic}" if topic else "db.read:*")
        return db.events_matching(
            topic=topic,
            command_run_id=step,
            pipeline_id=pipeline,
            limit=limit,
        )

    def topics(self) -> list[str]:
        """Return known event topics after auditing broad DB read access."""
        db = self.require_event_store(f"{self.context.source} event topics")
        self.context.audit_capability("db.read:*")
        return db.topics()

    def require_event_store(self, label: str) -> EventStore:
        """Return the backing event store without auditing raw DB access."""
        if self.context._db is None:
            raise ValueError(f"{label} requires an active database")
        return self.context._db
