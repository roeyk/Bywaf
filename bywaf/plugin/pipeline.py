"""Plugin-facing pipeline control helpers.

Provides the mediated pipeline API exposed as `context.pipeline`.

Used by:
- plugin.context: expose pipeline control to commandlets.
- runner.stages: catch intentional pipeline stops separately from failures.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import CommandContext


@dataclass(frozen=True, slots=True)
class PipelineStop(Exception):
    """Raised internally when a plugin intentionally stops its pipeline."""

    reason: str

    def __str__(self) -> str:
        """Return the operator-facing stop reason."""
        return self.reason


class ContextPipeline:
    """Mediated pipeline control API for commandlets."""

    def __init__(self, context: CommandContext) -> None:
        self._context = context

    def stop(self, reason: str = "pipeline stopped by plugin") -> None:
        """Request that the current pipeline stop after this commandlet."""
        normalized = reason.strip() or "pipeline stopped by plugin"
        payload = {
            "reason": normalized,
            "source": self._context.source,
            "command_run_id": self._context.command_run_id,
            "pipeline_id": self._context.pipeline_id,
            "job_id": self._context.job_id,
        }
        self._context.request("framework.pipeline.stop.requested", payload)
        if self._context._db is not None and self._context.pipeline_id:
            self._context._db.request_cancellation("pipeline", self._context.pipeline_id, reason=normalized)
        raise PipelineStop(normalized)
