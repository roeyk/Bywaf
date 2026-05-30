"""Low-level runtime control operations.

Updates job/pipeline/step runtime state, sends hard OS process signals when
requested, and prints queued control actions.

Used by:
- runtime.control_actions: apply resolved control and signal requests."""

from __future__ import annotations

import os
import signal

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import cancel_job, kill_job

from .control_selectors import display_target_kind


def pause_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Record or apply a pause request for one job."""
    from .control_actions import publish_runtime_signal

    events = context.event_store("job pause")
    runtime = context.runtime_store("job pause")
    context.audit_capability("framework.job.control")
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "pause", {}, mode="hard" if hard else "soft")
    events.publish(
        "job.pause.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGSTOP)
    runtime.update_job_status(int(row["id"]), "paused" if hard else "pausing")
    context.output(f"{'hard' if hard else 'soft'} pause requested for job {row['id']}")


def resume_job(context: CommandContext, row, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Record or apply a resume request for one job."""
    from .control_actions import publish_runtime_signal

    events = context.event_store("job resume")
    runtime = context.runtime_store("job resume")
    context.audit_capability("framework.job.control")
    if listonly:
        print_queued_actions(context, "job", str(row["id"]))
        return
    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "resume", {}, mode="hard" if hard else "soft")
    events.publish(
        "job.resume.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        signal_job_process(row, signal.SIGCONT)
    runtime.update_job_status(int(row["id"]), "running")
    context.output(f"resume requested for job {row['id']}")


def stop_job(context: CommandContext, row, *, hard: bool, publish_signal: bool = True) -> None:
    """Soft-cancel or hard-kill one job."""
    from .control_actions import publish_runtime_signal

    if publish_signal:
        publish_runtime_signal(context, "job", str(row["id"]), "stop", {}, mode="hard" if hard else "soft")
    context.event_store("job stop").publish(
        "job.stop.requested",
        {"job_id": row["id"], "mode": "hard" if hard else "soft"},
        "framework",
    )
    if hard:
        kill_job(context, row)
    else:
        cancel_job(context, row)


def pause_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause all jobs associated with a pipeline."""
    from .control_actions import publish_runtime_signal

    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "pause", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline pause").jobs_for_pipeline(resolved_pipeline_id):
        pause_job(context, job, hard=hard, publish_signal=False)


def resume_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume all jobs associated with a pipeline."""
    from .control_actions import publish_runtime_signal

    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal and not listonly:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "resume", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline resume").jobs_for_pipeline(resolved_pipeline_id):
        resume_job(context, job, hard=hard, listonly=listonly, publish_signal=False)


def stop_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop all jobs associated with a pipeline."""
    from .control_actions import publish_runtime_signal

    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "stop", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline stop").jobs_for_pipeline(resolved_pipeline_id):
        stop_job(context, job, hard=hard, publish_signal=False)


def cancel_run(context: CommandContext, command_run_id: str) -> None:
    """Request cooperative cancellation for one pipeline step."""
    jobs = require_run_jobs(context, command_run_id)
    context.runtime_store("run cancel").request_cancellation("run", command_run_id)
    for job in jobs:
        cancel_job(context, job)
    context.output(f"cancel requested for step {command_run_id}")


def kill_run(context: CommandContext, command_run_id: str) -> None:
    """Hard-kill jobs associated with one pipeline step."""
    for job in require_run_jobs(context, command_run_id):
        kill_job(context, job)
    context.output(f"killed step {command_run_id}")


def pause_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause jobs associated with one pipeline step."""
    from .control_actions import publish_runtime_signal

    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "pause", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        pause_job(context, job, hard=hard, publish_signal=False)
    context.event_store("run pause").publish(
        "run.pause.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def resume_run(context: CommandContext, command_run_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume or inspect queued actions for one pipeline step."""
    from .control_actions import publish_runtime_signal

    if listonly:
        print_queued_actions(context, "run", command_run_id)
        return
    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "resume", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        resume_job(context, job, hard=hard, listonly=False, publish_signal=False)
    context.event_store("run resume").publish(
        "run.resume.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def stop_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop jobs associated with one pipeline step."""
    from .control_actions import publish_runtime_signal

    if publish_signal:
        publish_runtime_signal(context, "run", command_run_id, "stop", {}, mode="hard" if hard else "soft")
    for job in require_run_jobs(context, command_run_id):
        stop_job(context, job, hard=hard, publish_signal=False)
    context.event_store("run stop").publish(
        "run.stop.requested",
        {"command_run_id": command_run_id, "mode": "hard" if hard else "soft"},
        "framework",
        command_run_id=command_run_id,
    )


def require_run_jobs(context: CommandContext, command_run_id: str):
    """Return jobs associated with a run or raise a clear error."""
    jobs = context.runtime_store("run jobs").jobs_for_run(command_run_id)
    if not jobs:
        raise ValueError(f"unknown or inactive step: {command_run_id}")
    return jobs


def require_pipeline_id(context: CommandContext, pipeline_id: str) -> str:
    """Validate that a pipeline exists and return its ID."""
    runtime = context.runtime_store("pipeline")
    if pipeline_id not in {str(row["pipeline_id"]) for row in runtime.pipelines(active_only=False)}:
        raise ValueError(f"unknown pipeline: {pipeline_id}")
    return pipeline_id


def signal_job_process(row, sig: signal.Signals) -> None:
    """Send a hard-control signal to a recorded job process."""
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        raise ValueError(f"job {row['id']} process is not running") from None


def print_queued_actions(context: CommandContext, target_type: str, target_id: str) -> None:
    """Print queued control events for a job, pipeline, or step target."""
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
    """Return whether a control event belongs to a selected runtime target."""
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
