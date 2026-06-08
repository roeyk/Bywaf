"""Plugin-facing live-control signal helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..event import Event

if TYPE_CHECKING:
    from .context import CommandContext


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
