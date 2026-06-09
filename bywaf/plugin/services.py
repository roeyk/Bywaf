"""Plugin-facing service helpers for command contexts.

Provides the scoped APIs that commandlets access through CommandContext for
secrets, events, signals, rendering, and artifacts.

Used by:
- plugin_context: constructs helpers from CommandContext properties.
- bundled and external plugins: interact with framework services indirectly."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..artifacts import artifact_store_for_event_store
from ..db import EventStore
from ..event import Event
from .. import policy as network_policy
from ..rendering import Table, render_console_table
from ..varstore import VarStore
from .services_events import ContextEvents as ContextEvents
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
