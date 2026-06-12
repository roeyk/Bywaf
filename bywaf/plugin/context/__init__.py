"""Runtime command context for commandlets.

Provides `CommandContext`, the object that commandlets use to reach framework
state and mediated services during execution.

Used by:
- runner: builds command contexts before commandlet execution.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- bundled and external plugins: access framework services without raw coupling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...artifacts import artifact_store_for_db
from ...db import EventStore
from .output import ContextOutputMixin
from .policy import ContextPolicyAuditMixin
from ..process import ContextProcess
from ..pipeline import ContextPipeline
from ..services import (
    ContextArtifacts,
    ContextEvents,
    ContextPolicy,
    ContextRender,
    ContextSecrets,
    ContextSignals,
)
from ...secret.store import InMemorySecretStore
from ...stores import ArtifactStoreProtocol, EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol
from ...varstore import ScopedVarStore, VarStore


@dataclass(init=False, slots=True)
class CommandContext(ContextOutputMixin, ContextPolicyAuditMixin):
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
    def policy(self) -> "ContextPolicy":
        """Return mediated policy helpers for plugin code."""
        return ContextPolicy(self)

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
    def pipeline(self) -> ContextPipeline:
        """Return mediated control over the current pipeline."""
        return ContextPipeline(self)

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

    def artifact_store(
        self,
        label: str | None = None,
        *,
        read_access: bool = False,
        write_access: bool = False,
    ) -> ArtifactStoreProtocol:
        """Return the paired artifact store for framework/internal commandlets."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active artifact storage")
        if read_access:
            self.audit_capability("artifact.read")
        if write_access:
            self.audit_capability("artifact.write")
        return artifact_store_for_db(self._db)

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


def command_run_id(context: CommandContext) -> str:
    """Return the current pipeline step ID or a stable interactive fallback."""
    return context.command_run_id or "interactive"


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)
