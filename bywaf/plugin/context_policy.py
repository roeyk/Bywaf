"""Command context capability and topic policy helpers.

Used by: `plugin.context.CommandContext` as a mixin. This keeps policy/audit
decisions separate from context construction and service accessor properties,
while preserving the public `CommandContext` API that plugins call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..event import Event
from .capabilities import (
    capability_declared,
    database_action_allowed,
    database_action_for_capability,
    framework_request_capability,
)

if TYPE_CHECKING:
    from ..db import EventStore
    from ..varstore import ScopedVarStore


class ContextPolicyAuditMixin:
    """Capability, database-action, and topic-contract policy for contexts.

    Mixed into: `CommandContext`.

    Called by: framework services, process helpers, plugin code that explicitly
    audits a capability, and context event/request methods.
    """

    _db: EventStore | None
    source: str
    metadata: dict[str, Any]
    _vars: ScopedVarStore

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
        """Return the capability enforcement mode for this commandlet."""
        configured = self._vars.get_global("capabilities.mode")
        fallback = str(self.metadata.get("capability_mode") or "audit")
        mode = (configured or fallback).strip().lower()
        return mode if mode in {"off", "audit", "warn", "enforce"} else "audit"

    @property
    def schema_validation_mode(self) -> str:
        """Return whether schema-backed plugin events are strictly validated."""
        configured = self._vars.get_global("schema.validation")
        fallback = str(self.metadata.get("schema_validation_mode") or "strict")
        mode = (configured or fallback).strip().lower()
        if mode in {"off", "false", "no", "0"}:
            return "off"
        return "strict"

    @property
    def declared_emits(self) -> tuple[str, ...] | None:
        """Return declared emitted topics, or None when no contract is known."""
        if "emits" not in self.metadata:
            return None
        value = self.metadata.get("emits", ())
        return tuple(str(topic) for topic in value)

    @property
    def topic_contract_mode(self) -> str:
        """Return policy mode for publishing topics outside declared emits."""
        configured = self._vars.get_global("topic.contract.mode")
        fallback = str(self.metadata.get("topic_contract_mode") or "audit")
        mode = (configured or fallback).strip().lower()
        return mode if mode in {"off", "audit", "warn", "enforce"} else "audit"

    @property
    def unregistered_topic_mode(self) -> str:
        """Return policy mode for declared topics without registered schemas."""
        configured = self._vars.get_global("topic.unregistered.mode")
        fallback = str(self.metadata.get("unregistered_topic_mode") or "audit")
        mode = (configured or fallback).strip().lower()
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
