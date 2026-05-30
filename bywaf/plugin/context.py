"""Runtime command context for commandlets.

Provides `CommandContext`, the object that commandlets use to reach framework
state and mediated services during execution.

Used by:
- runner: builds command contexts before commandlet execution.
- bundled and external plugins: access framework services without raw coupling."""

from __future__ import annotations

import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifacts import artifact_store_for_event_store
from ..db import EventStore
from ..events import Event
from .capabilities import (
    capability_declared,
    database_action_allowed,
    database_action_for_capability,
    framework_request_capability,
)
from .process import ContextProcess
from .services import (
    ContextArtifacts,
    ContextEvents,
    ContextRender,
    ContextSecrets,
    ContextSignals,
    progress_payload,
    should_emit_progress,
)
from ..rendering import Column, Table
from ..secret.store import InMemorySecretStore
from ..stores import ArtifactStoreProtocol, EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol
from ..varstore import ScopedVarStore, VarStore


@dataclass(init=False, slots=True)
class CommandContext:
    """Runtime context passed into commandlets.

    This is the plugin author's mediated view of Bywaf runtime state.  It
    exposes scoped variables, event publishing, artifacts, rendering, signals,
    and process helpers while keeping raw database access reserved for internal
    commandlets that explicitly request it.
    """

    _db: EventStore | None
    source: str
    _vars: ScopedVarStore
    _secrets: InMemorySecretStore
    metadata: dict[str, Any]

    def __init__(
        self,
        db: EventStore | None,
        source: str,
        _varstore: VarStore | None = None,
        _secrets: InMemorySecretStore | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Create a command context while preserving the public `db=` keyword."""
        self._db = db
        self.source = source
        self.metadata = metadata or {}
        # Scope variables at context construction time.  The underlying
        # VarStore remains shared, but `ScopedVarStore` enforces commandlet,
        # provider, and snapshot lookup rules for this specific step.
        self._vars = ScopedVarStore(
            _varstore or VarStore(),
            str(self.metadata.get("var_scope") or self.source),
            str(self.metadata.get("provider_scope") or ""),
            set(self.metadata.get("provider_variables") or ()),
            self.metadata.get("run_vars", {}),
        )
        self._secrets = _secrets or InMemorySecretStore()

    @property
    def db(self) -> EventStore | None:
        """Return raw database access for privileged/internal commandlets.

        Most plugins should use `context.events`, `context.artifacts`, and other
        mediated services.  Accessing `db` is audited as `db.raw` because it
        bypasses those narrower APIs.
        """
        if self._db is not None:
            self.audit_capability("db.raw")
        return self._db

    @db.setter
    def db(self, value: EventStore | None) -> None:
        """Replace the raw database handle for internal DB-management code."""
        self._db = value

    @property
    def vars(self) -> ScopedVarStore:
        """Return this commandlet's scoped variable view."""
        return self._vars

    @property
    def secrets(self) -> "ContextSecrets":
        """Return the mediated secret resolver for opaque secret references."""
        return ContextSecrets(self)

    @property
    def events(self) -> "ContextEvents":
        """Return the mediated event-bus API for plugin code."""
        return ContextEvents(self)

    @property
    def process(self) -> ContextProcess:
        """Return the mediated process-execution API for plugin code."""
        return ContextProcess(self)

    @property
    def artifacts(self) -> "ContextArtifacts":
        """Return the mediated artifact API for plugin code."""
        return ContextArtifacts(self)

    @property
    def render(self) -> "ContextRender":
        """Return the mediated rendering API for plugin code."""
        return ContextRender(self)

    @property
    def signals(self) -> "ContextSignals":
        """Return live-control signals addressed to this commandlet run."""
        return ContextSignals(self)

    @property
    def pipeline_id(self) -> str | None:
        """Return the current pipeline ID, if this commandlet has one."""
        value = self.metadata.get("pipeline_id")
        return str(value) if value is not None else None

    @property
    def command_run_id(self) -> str | None:
        """Return the current pipeline-step ID, if this commandlet has one."""
        value = self.metadata.get("command_run_id")
        return str(value) if value is not None else None

    @property
    def parent_command_run_id(self) -> str | None:
        """Return the upstream pipeline-step ID for a pipeline stage, if present."""
        value = self.metadata.get("parent_command_run_id")
        return str(value) if value is not None else None

    @property
    def job_id(self) -> int | str | None:
        """Return the active job ID, if this commandlet is job-scoped."""
        return self.metadata.get("job_id")

    @property
    def note(self) -> str | None:
        """Return the framework-level `note=` text for this pipeline step."""
        value = self.metadata.get("note")
        return str(value) if value is not None else None

    @property
    def background(self) -> bool:
        """Return whether this commandlet is running as a background stage."""
        return bool(self.metadata.get("background"))

    @property
    def input_high_watermark(self) -> int:
        """Return the highest upstream event ID already consumed."""
        value = self.metadata.get("input_high_watermark", 0)
        return int(value) if value is not None else 0

    def require_db(self, label: str | None = None) -> EventStore:
        """Return the active DB or raise a consistent user-facing error."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires an active database")
        self.audit_capability("db.raw")
        return self._db

    def event_store(self, label: str | None = None) -> EventStoreProtocol:
        """Return the event/audit store without exposing raw DB maintenance."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires an active event store")
        return self._db

    def runtime_store(self, label: str | None = None) -> RuntimeStoreProtocol:
        """Return runtime metadata storage for jobs, runs, and pipelines."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active runtime storage")
        return self._db

    def maintenance_store(self, label: str | None = None) -> MaintenanceStoreProtocol:
        """Return privileged storage-maintenance operations."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active storage maintenance")
        self.audit_capability("db.raw")
        return self._db

    def artifact_store(self, label: str | None = None) -> ArtifactStoreProtocol:
        """Return the paired artifact store for framework/internal commandlets."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active artifact storage")
        return artifact_store_for_event_store(self._db)

    def require_foreground(self, label: str | None = None) -> None:
        """Raise if a foreground-only commandlet is running in the background."""
        if self.background:
            raise ValueError(f"{label or self.source} must run in the foreground")

    def cancelled(self) -> bool:
        """Return whether this job, pipeline, or pipeline step was cancelled."""
        if self._db is None:
            return False
        return self._db.cancellation_requested(
            job_id=self.job_id,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
        )

    def raise_if_cancelled(self) -> None:
        """Raise a clear exception when a soft-cancellation request is pending."""
        if self.cancelled():
            raise RuntimeError("commandlet cancelled")

    def request(self, topic: str, payload: dict[str, Any]) -> Event | None:
        """Write a framework request event with this commandlet's run scope.

        Framework requests are not just logs: they are durable requests for a
        mediated framework action.  The matching capability is audited against
        the commandlet declaration after the request event is written.
        """
        if self._db is None:
            return None
        capability = framework_request_capability(topic)
        if (
            capability is not None
            and self.capability_mode == "enforce"
            and not capability_declared(capability, self.declared_capabilities)
        ):
            # Deny before recording a framework request that a later handler
            # might otherwise execute. The capability evidence is still
            # recorded without a request_event_id.
            self.audit_capability(capability)
        event = self._db.publish(
            topic,
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        if capability is not None:
            self.audit_capability(capability, request_event_id=event.id)
        return event

    def audit_capability(self, capability: str, *, request_event_id: int | None = None) -> None:
        """Record audit-only capability usage for this commandlet run."""
        if self._db is None:
            return
        mode = self.capability_mode
        if mode == "off":
            return
        self.enforce_database_action_policy(capability)
        declared = capability_declared(capability, self.declared_capabilities)
        if request_event_id is None:
            # Avoid spamming identical audit events for repeated ordinary reads
            # or writes in the same commandlet step.  Request-linked capability
            # events are not deduped because each request has its own event id.
            audited = self.metadata.setdefault("_audited_capabilities", set())
            audit_key = (self.source, self.command_run_id, capability, declared)
            if audit_key in audited:
                return
            audited.add(audit_key)
        payload = {
            "commandlet": self.source,
            "capability": capability,
            "declared": declared,
            "request_event_id": request_event_id,
            "job_id": self.job_id,
        }
        self._db.publish(
            "plugin.capability.used",
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        if not declared:
            self._db.publish(
                "plugin.capability.missing",
                payload,
                self.source,
                pipeline_id=self.pipeline_id,
                command_run_id=self.command_run_id,
                parent_command_run_id=self.parent_command_run_id,
            )
            if mode == "enforce":
                raise PermissionError(f"{self.source} capability policy denies undeclared capability: {capability}")

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        """Return capabilities declared or implied for this commandlet."""
        value = self.metadata.get("capabilities", ())
        return tuple(str(capability) for capability in value)

    @property
    def database_actions(self) -> tuple[str, ...]:
        """Return coarse database actions allowed for this commandlet."""
        value = self.metadata.get("database_actions", ())
        return tuple(str(action) for action in value)

    @property
    def capability_mode(self) -> str:
        """Return the global capability enforcement mode."""
        mode = (self.vars.get_global("capabilities.mode", "audit") or "audit").strip().lower()
        return mode if mode in {"off", "audit", "warn", "enforce"} else "audit"

    def enforce_database_action_policy(self, capability: str) -> None:
        """Reject DB capabilities outside this commandlet's action policy."""
        required = database_action_for_capability(capability)
        if required is None:
            return
        allowed = self.database_actions
        if not allowed or database_action_allowed(required, allowed):
            return
        allowed_text = ", ".join(allowed)
        raise PermissionError(f"{self.source} database action policy denies {capability}; allowed: {allowed_text}")

    def output(self, text: object = "", *, end: str = "\n") -> None:
        """Request normal command output from the framework console."""
        payload = {
            "text": str(text),
            "end": end,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.output.requested", payload) is None:
            print(str(text), end=end, flush=True)

    def table(
        self,
        rows: Iterable[Mapping[str, object] | Sequence[object]],
        columns: Sequence[str | Column] | None = None,
        *,
        title: str | None = None,
    ) -> None:
        """Render a structured table through the framework output path."""
        self.render.table(Table.from_rows(rows, columns, title=title))

    def alert(self, message: str, *, level: str = "alert", silent: bool = False) -> None:
        """Request a framework-owned console alert."""
        payload = {
            "message": message,
            "level": level,
            "silent": silent,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.alert.requested", payload) is None and not silent:
            print(f"{self.source} <{command_run_id(self)}>: {message}", flush=True)

    def progress_started(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-started event."""
        return self.progress(
            status="started",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress(
        self,
        *,
        phase: str,
        status: str = "updated",
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit a structured progress event subject to framework throttling."""
        payload = progress_payload(
            self,
            status=status,
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            extra=extra,
        )
        return self.publish_progress_payload(payload)

    def progress_completed(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-completed event."""
        return self.progress(
            status="completed",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress_failed(
        self,
        *,
        phase: str,
        message: str | None = None,
        error: str | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-failed event."""
        payload_extra = dict(extra)
        if error is not None:
            payload_extra["error"] = error
        payload = progress_payload(
            self,
            status="failed",
            phase=phase,
            current=None,
            total=None,
            unit=None,
            message=message,
            target=None,
            eta_seconds=None,
            extra=payload_extra,
        )
        return self.publish_progress_payload(payload)

    def publish_progress_payload(self, payload: Mapping[str, object]) -> Event | None:
        """Publish one progress payload after applying throttle policy."""
        if not should_emit_progress(self, payload):
            return None
        if self._db is None:
            return None
        status = str(payload.get("status", "updated"))
        self.audit_capability("plugin.progress")
        event = self._db.publish(
            f"plugin.progress.{status}",
            dict(payload),
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        self.metadata["_progress_last"] = {
            "monotonic": time.monotonic(),
            "phase": payload.get("phase"),
            "percent": payload.get("percent"),
            "status": status,
        }
        return event

    def page_file(self, path: str | Path) -> None:
        """Request framework-owned file paging for terminal and GUI frontends."""
        file_path = Path(path).expanduser()
        payload = {
            "path": str(file_path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
        }
        if self.request("framework.file.page.requested", payload) is None:
            print(file_path.read_text(errors="replace"), end="", flush=True)

    def page_text(self, text: object, *, suffix: str = ".txt") -> None:
        """Page generated text through the same framework path as local files."""
        content = str(text)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as handle:
            handle.write(content)
            if content and not content.endswith("\n"):
                handle.write("\n")
            path = Path(handle.name)
        payload = {
            "path": str(path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
            "temporary": True,
        }
        if self.request("framework.file.page.requested", payload) is None:
            try:
                print(path.read_text(errors="replace"), end="", flush=True)
            finally:
                path.unlink(missing_ok=True)



def command_run_id(context: CommandContext) -> str:
    """Return the current pipeline step ID or a stable interactive fallback."""
    return context.command_run_id or "interactive"


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)
