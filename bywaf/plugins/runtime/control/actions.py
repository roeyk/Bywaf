"""Runtime control action handlers.

Applies pause, resume, stop, end, and cancellation requests to jobs, pipelines,
and pipeline steps after selectors have been resolved.

Used by:
- runtime.control: dispatch convenience control commandlets and framework signals."""

from __future__ import annotations

from collections.abc import Callable

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import cancel_job, kill_job, require_job
from bywaf.plugins.runtime.pipeline import cancel_pipeline, kill_pipeline

from .operations import (
    cancel_run,
    kill_run,
    pause_job,
    pause_pipeline,
    pause_run,
    resume_job,
    resume_pipeline,
    resume_run,
    stop_job,
    stop_pipeline,
    stop_run,
)
from .signals import publish_runtime_signal

ControlHandler = Callable[[CommandContext, str, bool, bool], None]
SignalHandler = Callable[[CommandContext, str, bool], None]


def dispatch_framework_signal(context: CommandContext, parsed: dict[str, object]) -> None:
    """Apply framework-native signal actions after publishing the signal."""
    action = str(parsed["action"])
    if action not in {"pause", "resume", "stop", "end"}:
        return
    kind = str(parsed["kind"])
    target_id = str(parsed["target_id"])
    hard = parsed["mode"] == "hard"
    handler = FRAMEWORK_SIGNAL_HANDLERS.get((action, kind))
    if handler is None:
        raise ValueError(f"unsupported signal target: {kind}={target_id}")
    # Keep publication and application separate so the audit trail records the
    # requested action even when a framework-level handler fails.
    handler(context, target_id, hard)


def control_cancel_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one job."""
    del hard, listonly
    publish_runtime_signal(context, "job", target_id, "stop", {}, mode="soft")
    cancel_job(context, require_job(context, target_id))


def control_cancel_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one pipeline."""
    del hard, listonly
    publish_runtime_signal(context, "pipeline", target_id, "stop", {}, mode="soft")
    cancel_pipeline(context, target_id)


def control_cancel_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Cancel one pipeline step."""
    del hard, listonly
    publish_runtime_signal(context, "run", target_id, "stop", {}, mode="soft")
    cancel_run(context, target_id)


def control_end_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one job."""
    del listonly
    publish_runtime_signal(context, "job", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_job(context, target_id, hard)


def control_end_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one pipeline."""
    del listonly
    publish_runtime_signal(context, "pipeline", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_pipeline(context, target_id, hard)


def control_end_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """End one pipeline step."""
    del listonly
    publish_runtime_signal(context, "run", target_id, "end", {}, mode="hard" if hard else "soft")
    signal_end_run(context, target_id, hard)


def control_pause_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one job."""
    del listonly
    pause_job(context, require_job(context, target_id), hard=hard)


def control_pause_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one pipeline."""
    del listonly
    pause_pipeline(context, target_id, hard=hard)


def control_pause_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Pause one pipeline step."""
    del listonly
    pause_run(context, target_id, hard=hard)


def control_resume_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one job."""
    resume_job(context, require_job(context, target_id), hard=hard, listonly=listonly)


def control_resume_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one pipeline."""
    resume_pipeline(context, target_id, hard=hard, listonly=listonly)


def control_resume_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Resume one pipeline step."""
    resume_run(context, target_id, hard=hard, listonly=listonly)


def control_stop_job(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one job."""
    del listonly
    stop_job(context, require_job(context, target_id), hard=hard)


def control_stop_pipeline(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one pipeline."""
    del listonly
    stop_pipeline(context, target_id, hard=hard)


def control_stop_run(context: CommandContext, target_id: str, hard: bool, listonly: bool) -> None:
    """Stop one pipeline step."""
    del listonly
    stop_run(context, target_id, hard=hard)


def signal_pause_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one job."""
    pause_job(context, require_job(context, target_id), hard=hard, publish_signal=False)


def signal_pause_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one pipeline."""
    pause_pipeline(context, target_id, hard=hard, publish_signal=False)


def signal_pause_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework pause signal to one pipeline step."""
    pause_run(context, target_id, hard=hard, publish_signal=False)


def signal_resume_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one job."""
    resume_job(context, require_job(context, target_id), hard=hard, listonly=False, publish_signal=False)


def signal_resume_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one pipeline."""
    resume_pipeline(context, target_id, hard=hard, listonly=False, publish_signal=False)


def signal_resume_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework resume signal to one pipeline step."""
    resume_run(context, target_id, hard=hard, listonly=False, publish_signal=False)


def signal_stop_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one job."""
    stop_job(context, require_job(context, target_id), hard=hard, publish_signal=False)


def signal_stop_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one pipeline."""
    stop_pipeline(context, target_id, hard=hard, publish_signal=False)


def signal_stop_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework stop signal to one pipeline step."""
    stop_run(context, target_id, hard=hard, publish_signal=False)


def signal_end_job(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one job."""
    if hard:
        kill_job(context, require_job(context, target_id))
    else:
        cancel_job(context, require_job(context, target_id))


def signal_end_pipeline(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one pipeline."""
    if hard:
        kill_pipeline(context, target_id)
    else:
        cancel_pipeline(context, target_id)


def signal_end_run(context: CommandContext, target_id: str, hard: bool) -> None:
    """Apply a framework end signal to one pipeline step."""
    if hard:
        kill_run(context, target_id)
    else:
        cancel_run(context, target_id)


# Operator control commands target jobs, pipelines, or runs with different DB
# actions. dispatch_control_action() uses this dispatch table to keep that matrix
# explicit.
CONTROL_HANDLERS: dict[tuple[str, str], ControlHandler] = {
    ("cancel", "job"): control_cancel_job,
    ("cancel", "pipeline"): control_cancel_pipeline,
    ("cancel", "run"): control_cancel_run,
    ("end", "job"): control_end_job,
    ("end", "pipeline"): control_end_pipeline,
    ("end", "run"): control_end_run,
    ("pause", "job"): control_pause_job,
    ("pause", "pipeline"): control_pause_pipeline,
    ("pause", "run"): control_pause_run,
    ("resume", "job"): control_resume_job,
    ("resume", "pipeline"): control_resume_pipeline,
    ("resume", "run"): control_resume_run,
    ("stop", "job"): control_stop_job,
    ("stop", "pipeline"): control_stop_pipeline,
    ("stop", "run"): control_stop_run,
}


# Framework signal events use the same action/target matrix but operate from
# stored signal payloads. dispatch_framework_signal() uses this separate dispatch table.
FRAMEWORK_SIGNAL_HANDLERS: dict[tuple[str, str], SignalHandler] = {
    ("end", "job"): signal_end_job,
    ("end", "pipeline"): signal_end_pipeline,
    ("end", "run"): signal_end_run,
    ("pause", "job"): signal_pause_job,
    ("pause", "pipeline"): signal_pause_pipeline,
    ("pause", "run"): signal_pause_run,
    ("resume", "job"): signal_resume_job,
    ("resume", "pipeline"): signal_resume_pipeline,
    ("resume", "run"): signal_resume_run,
    ("stop", "job"): signal_stop_job,
    ("stop", "pipeline"): signal_stop_pipeline,
    ("stop", "run"): signal_stop_run,
}
