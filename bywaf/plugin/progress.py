"""Progress payload and throttle helpers for command contexts.

Used by:
- plugin authors, command contexts, plugin checks, and runner commandlet execution.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import CommandContext


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
