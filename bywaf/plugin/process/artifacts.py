"""Helpers for process-output artifact diagnostics.

Provides small query helpers for wrapper plugins that need to link their
operational error events back to framework-mediated process transcripts.

Used by:
- plugin authors, command contexts, plugin checks, and runner commandlet execution.
"""

from __future__ import annotations

from typing import Any

from ..context import CommandContext


def proc_artifact_ref(context: CommandContext) -> dict[str, Any]:
    """Return the latest process-output artifact reference for the current step."""
    if context.command_run_id is None:
        return {}
    events = context.events.query(topic="process.run", step=context.command_run_id, limit=1)
    if not events:
        return {}
    payload = events[0].payload
    return {
        key: payload[key]
        for key in ("artifact_id", "artifact_row_id", "artifact_name", "artifact_sha256")
        if payload.get(key)
    }
