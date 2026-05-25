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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..artifacts import Artifact, artifact_store_for_event_store
from ..db import EventStore, Subscription
from ..events import Event
from ..rendering import Table, render_console_table
from ..varstore import VarStore

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


def progress_payload(
    context: CommandContext,
    *,
    status: str,
    phase: str,
    current: int | float | None,
    total: int | float | None,
    unit: str | None,
    message: str | None,
    target: str | None,
    eta_seconds: int | float | None,
    extra: Mapping[str, object],
) -> dict[str, object]:
    """Build one normalized progress payload."""
    payload: dict[str, object] = {
        "commandlet": context.source,
        "status": status,
        "phase": phase,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "parent_command_run_id": context.parent_command_run_id,
    }
    if current is not None:
        payload["current"] = current
    if total is not None:
        payload["total"] = total
    percent = progress_percent(current, total)
    if percent is not None:
        payload["percent"] = percent
    if unit is not None:
        payload["unit"] = unit
    if message is not None:
        payload["message"] = message
    if target is not None:
        payload["target"] = target
    if eta_seconds is not None:
        payload["eta_seconds"] = eta_seconds
    payload.update(extra)
    return payload


def progress_percent(current: int | float | None, total: int | float | None) -> float | None:
    """Return progress percent when current and total are usable."""
    if current is None or total is None or total <= 0:
        return None
    return round((float(current) / float(total)) * 100, 2)


def should_emit_progress(context: CommandContext, payload: Mapping[str, object]) -> bool:
    """Enforce framework progress throttling for one pipeline step."""
    status = str(payload.get("status", "updated"))
    if status in {"started", "completed", "failed"}:
        return True
    last = context.metadata.get("_progress_last")
    if not isinstance(last, Mapping):
        return True
    phase = payload.get("phase")
    if phase != last.get("phase"):
        return True
    interval_ms = progress_float_var(context, "progress.min-interval-ms", 250.0)
    last_time = last.get("monotonic")
    if isinstance(last_time, (int, float)) and (time.monotonic() - float(last_time)) * 1000 >= interval_ms:
        return True
    percent = payload.get("percent")
    last_percent = last.get("percent")
    if isinstance(percent, (int, float)) and isinstance(last_percent, (int, float)):
        delta = progress_float_var(context, "progress.min-percent-delta", 1.0)
        return abs(float(percent) - float(last_percent)) >= delta
    return False


def progress_float_var(context: CommandContext, name: str, default: float) -> float:
    """Read a global progress throttle setting with a safe fallback."""
    raw = context.vars.get_global(name, str(default))
    try:
        return float(raw) if raw is not None else default
    except ValueError:
        return default


@dataclass(slots=True)
class CompletionContext:
    """Lightweight context passed into optional plugin completion hooks."""

    db: EventStore | None = None
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ContextEvents:
    """Capability-aware event API exposed to commandlets."""

    context: CommandContext

    def publish(self, topic: str, payload: dict[str, Any]) -> Event:
        """Publish one event in the current commandlet scope."""
        db = self.require_event_store(f"{self.context.source} event publish")
        self.context.audit_capability(f"db.write:{topic}")
        return db.publish(
            topic,
            payload,
            self.context.source,
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

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


@dataclass(frozen=True, slots=True)
class ContextSignals:
    """Plugin-facing helper for framework live-control signals."""

    context: CommandContext

    def pending(self, *, action: str | None = None, after_id: int = 0, limit: int = 1000) -> list[Event]:
        """Return signals that apply to this job, pipeline, or run."""
        events = self.context.events.query(topic="runtime.signal.requested", limit=limit)
        matching = [
            event
            for event in events
            if (event.id or 0) > after_id
            and signal_applies_to_context(event, self.context)
            and (action is None or event.payload.get("action") == action)
        ]
        return matching

    def applied(self, request: Event, message: str = "", **details: object) -> Event:
        """Publish that this commandlet applied a live-control signal."""
        return self._respond("runtime.signal.applied", request, message, details)

    def ignored(self, request: Event, message: str = "", **details: object) -> Event:
        """Publish that this commandlet ignored a live-control signal."""
        return self._respond("runtime.signal.ignored", request, message, details)

    def _respond(self, topic: str, request: Event, message: str, details: dict[str, object]) -> Event:
        payload = {
            "request_event_id": request.id,
            "action": request.payload.get("action"),
            "message": message,
            "details": details,
        }
        return self.context.events.publish(topic, payload)


def signal_applies_to_context(event: Event, context: CommandContext) -> bool:
    """Return whether one runtime signal is scoped to this command context."""
    target_type = event.payload.get("target_type")
    target_id = str(event.payload.get("target_id", ""))
    return (
        (target_type == "run" and context.command_run_id == target_id)
        or (target_type == "pipeline" and context.pipeline_id == target_id)
        or (target_type == "job" and context.job_id is not None and str(context.job_id) == target_id)
    )


@dataclass(frozen=True, slots=True)
class ContextArtifacts:
    """Framework-mediated artifact API exposed to commandlets."""

    context: CommandContext

    def attach_file(
        self,
        path: str | Path,
        *,
        name: str | None = None,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> Artifact:
        """Attach one file to the paired artifact store and audit it."""
        db = self.require_event_store("artifact attach")
        self.context.audit_capability("filesystem.read")
        self.context.audit_capability("artifact.write")
        artifact = artifact_store_for_event_store(db).attach_file(
            Path(path),
            name=name,
            note=note,
            commandlet=self.context.source,
            job_id=job_id if job_id is not None else self.context.job_id,
            pipeline_id=pipeline_id if pipeline_id is not None else self.context.pipeline_id,
            command_run_id=command_run_id if command_run_id is not None else self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )
        self.publish_attached(artifact)
        return artifact

    def attach_files(
        self,
        paths: Iterable[str | Path],
        *,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Attach several files to the same run/job/pipeline provenance."""
        return [
            self.attach_file(
                path,
                note=note,
                job_id=job_id,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
            )
            for path in paths
        ]

    def publish_attached(self, artifact: Artifact) -> Event | None:
        """Record artifact provenance in the main event database."""
        if self.context._db is None:
            return None
        payload = artifact_event_payload(artifact)
        return self.context._db.publish(
            "artifact.attached",
            payload,
            "framework",
            pipeline_id=artifact.pipeline_id,
            command_run_id=artifact.command_run_id,
            parent_command_run_id=artifact.parent_command_run_id,
        )

    def require_event_store(self, label: str) -> EventStore:
        """Return the backing event store without exposing raw DB writes."""
        if self.context._db is None:
            raise ValueError(f"{label} requires an active database")
        return self.context._db


def artifact_event_payload(artifact: Artifact) -> dict[str, Any]:
    """Return the main-DB audit payload for one artifact row."""
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_row_id": artifact.id,
        "name": artifact.name,
        "content_type": artifact.content_type,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "created_at": artifact.created_at,
        "source_path": artifact.source_path,
        "commandlet": artifact.commandlet,
        "job_id": artifact.job_id,
        "pipeline_id": artifact.pipeline_id,
        "command_run_id": artifact.command_run_id,
        "parent_command_run_id": artifact.parent_command_run_id,
        "note": artifact.note,
    }
