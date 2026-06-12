"""Queued runtime-control display helpers.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext

from .selectors import display_target_kind


def print_queued_actions(context: CommandContext, target_type: str, target_id: str) -> None:
    """Print queued control events for a job, pipeline, or step target.

    Called by: resume operations in `job_operations` and `target_operations`
    when the operator passes `--listonly`.
    """
    display_type = display_target_kind(target_type)
    context.output(f"queued resume actions for {display_type} {target_id}:")
    events = [
        event
        for event in context.event_store("control queued actions").events_matching(limit=100000)
        if event.topic.endswith(".pause.requested")
        or event.topic.endswith(".resume.requested")
        or event.topic.endswith(".stop.requested")
        or event.topic == "runtime.signal.requested"
    ]
    matching = [event for event in events if control_event_matches(event, target_type, target_id)]
    if not matching:
        context.output("none")
        return
    for event in matching:
        mode = event.payload.get("mode", "")
        action = event.payload.get("action", "")
        suffix = f" action={action}" if action else ""
        context.output(f"{event.created_at.isoformat()} {event.topic} {display_type}={target_id} mode={mode}{suffix}")


def control_event_matches(event: Event, target_type: str, target_id: str) -> bool:
    """Return whether a control event belongs to a selected runtime target.

    Called by: `print_queued_actions()`.
    """
    if target_type == "job":
        return str(event.payload.get("job_id")) == target_id or (
            event.payload.get("target_type") == "job" and str(event.payload.get("target_id")) == target_id
        )
    if target_type == "pipeline":
        return (
            event.pipeline_id == target_id
            or event.payload.get("pipeline_id") == target_id
            or (event.payload.get("target_type") == "pipeline" and event.payload.get("target_id") == target_id)
        )
    if target_type == "run":
        return (
            event.command_run_id == target_id
            or event.payload.get("command_run_id") == target_id
            or (event.payload.get("target_type") == "run" and event.payload.get("target_id") == target_id)
        )
    return False
