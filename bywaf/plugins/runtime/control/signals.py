"""Runtime control signal publication.

Provides the canonical audit event for pause, resume, stop, end, and cancel
requests without coupling action dispatch to low-level control operations.

Used by:
- runtime.control: publish ad hoc framework signals.
- runtime.control.actions and focused control helpers: record requested control
  work.
"""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext


def publish_runtime_signal(
    context: CommandContext,
    target_type: str,
    target_id: str,
    action: str,
    args: dict[str, str],
    *,
    mode: str,
) -> Event:
    """Publish the canonical audited runtime signal event."""
    events = context.event_store("signal")
    # Signals are durable coordination records first. Some actions are also
    # applied immediately by the framework, but commandlets can independently
    # observe these events for cooperative live control.
    if target_type in {"job", "run"}:
        context.audit_capability("framework.job.control")
    if target_type in {"pipeline", "run"}:
        context.audit_capability("framework.pipeline.control")
    payload = {
        "target_type": target_type,
        "target_id": target_id,
        "action": action,
        "args": args,
        "mode": mode,
    }
    if target_type == "job":
        payload["job_id"] = target_id
    if target_type == "pipeline":
        payload["pipeline_id"] = target_id
    if target_type == "run":
        payload["command_run_id"] = target_id
    return events.publish(
        "runtime.signal.requested",
        payload,
        "framework",
        pipeline_id=target_id if target_type == "pipeline" else None,
        command_run_id=target_id if target_type == "run" else None,
    )
