"""Plugin-facing service helpers for command contexts.

Provides the scoped APIs that commandlets access through CommandContext for
secrets, events, signals, rendering, and artifacts.

Used by:
- plugin_context: constructs helpers from CommandContext properties.
- bundled and external plugins: interact with framework services indirectly."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..artifacts import artifact_store_for_event_store
from ..db import EventStore, Subscription
from ..event.schemas import EventSchemaObject, event_schema, schema_objects, validate_event_payload
from ..event import Event
from .. import policy as network_policy
from ..rendering import Table, render_console_table
from ..varstore import VarStore
from .services_artifacts import (
    ContextArtifacts as ContextArtifacts,
    artifact_event_payload as artifact_event_payload,
    attach_generated_artifact as attach_generated_artifact,
)
from .progress import (
    progress_float_var as progress_float_var,
    progress_payload as progress_payload,
    progress_percent as progress_percent,
    should_emit_progress as should_emit_progress,
)
from .signals import (
    ContextSignals as ContextSignals,
    signal_applies_to_context as signal_applies_to_context,
)

if TYPE_CHECKING:
    from .context import CommandContext


@dataclass(frozen=True, slots=True)
class ContextSecrets:
    """Narrow secret-resolution API exposed to commandlets."""

    context: CommandContext

    def resolve(self, value: str | None, default: str | None = None) -> str | None:
        """Resolve an opaque secret reference, or pass through normal text."""
        if value is None or value == "":
            return default
        secret = self.context._secrets.get(value)
        if secret is None:
            return value
        self.context.audit_capability("framework.secret.resolve")
        return secret

    def fingerprint(self, value: str | None) -> str | None:
        """Return an audit-safe fingerprint for an opaque secret reference."""
        metadata = self.context._secrets.metadata(value or "")
        return metadata.fingerprint.format() if metadata is not None else None

    def is_secret_ref(self, value: str | None) -> bool:
        """Return whether a value is an in-memory secret reference."""
        return self.context._secrets.is_ref(value)


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    """Framework-mediated policy API exposed to commandlets."""

    context: CommandContext

    def resolve_target(self, target: str) -> tuple[str, ...]:
        """Resolve one network target through the framework policy layer."""
        return network_policy.resolve_target(target)

    def network_policy(self) -> tuple[tuple[Any, ...], tuple[Any, ...], str]:
        """Return configured network allow/deny policy."""
        return network_policy.network_policy(self.context)

    def evaluate_network_targets(self, targets: Iterable[str]) -> tuple[tuple[str, ...], list[str]]:
        """Return allowed targets and warnings without auditing a decision."""
        before = tuple(dict.fromkeys(targets))
        if not before:
            return (), []
        allowed, denied, _mode = self.network_policy()
        return network_policy.apply_network_policy(before, allowed, denied)

    def filter_network_targets(self, targets: Iterable[str]) -> tuple[str, ...]:
        """Return targets allowed by network policy and audit pruning."""
        before = tuple(dict.fromkeys(targets))
        if not before:
            return ()
        after, warnings = self.evaluate_network_targets(before)
        if warnings:
            for warning in warnings:
                self.context.alert(warning)
            network_policy.publish_network_policy_evaluated(
                self.context,
                decision="warn",
                warnings=warnings,
                before=before,
                after=after,
            )
        return after


@dataclass(frozen=True, slots=True)
class ContextRender:
    """Framework-mediated rendering API exposed to commandlets."""

    context: CommandContext

    def table(self, table: Table) -> Event | None:
        """Request rendering of one structured table."""
        payload = {
            **table.to_payload(),
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "row_count": len(table.rows),
        }
        event = self.context.request("framework.render.table.requested", payload)
        if event is None:
            rendered = render_console_table(table)
            if rendered:
                print(rendered, flush=True)
        return event


@dataclass(slots=True)
class CompletionContext:
    """Lightweight context passed into optional plugin completion hooks."""

    db: EventStore | None = None
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)

    def event_store(self, label: str | None = None) -> EventStore:
        """Return the event/audit store for completion helpers."""
        if self.db is None:
            raise ValueError(f"{label or 'completion'} requires an active event store")
        return self.db

    def runtime_store(self, label: str | None = None) -> EventStore:
        """Return runtime metadata storage for completion helpers."""
        if self.db is None:
            raise ValueError(f"{label or 'completion'} requires active runtime storage")
        return self.db

    def artifact_store(self, label: str | None = None):
        """Return artifact storage for completion helpers."""
        if self.db is None:
            raise ValueError(f"{label or 'completion'} requires active artifact storage")
        return artifact_store_for_event_store(self.db)


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
