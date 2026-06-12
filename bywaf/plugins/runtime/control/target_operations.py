"""Runtime control operations for pipelines and pipeline steps.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import cancel_job, kill_job

from .job_operations import pause_job, resume_job, stop_job
from .queued_actions import print_queued_actions
from .signals import publish_runtime_signal


def pause_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause all jobs associated with a pipeline.

    Called by: `runtime.control.actions`.
    """
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "pause", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline pause").jobs_for_pipeline(resolved_pipeline_id):
        pause_job(context, job, hard=hard, publish_signal=False)


def resume_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, listonly: bool, publish_signal: bool = True) -> None:
    """Resume all jobs associated with a pipeline.

    Called by: `runtime.control.actions`.
    """
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal and not listonly:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "resume", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline resume").jobs_for_pipeline(resolved_pipeline_id):
        resume_job(context, job, hard=hard, listonly=listonly, publish_signal=False)


def stop_pipeline(context: CommandContext, pipeline_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Stop all jobs associated with a pipeline.

    Called by: `runtime.control.actions`.
    """
    resolved_pipeline_id = require_pipeline_id(context, pipeline_id)
    if publish_signal:
        publish_runtime_signal(context, "pipeline", resolved_pipeline_id, "stop", {}, mode="hard" if hard else "soft")
    for job in context.runtime_store("pipeline stop").jobs_for_pipeline(resolved_pipeline_id):
        stop_job(context, job, hard=hard, publish_signal=False)


def cancel_run(context: CommandContext, command_run_id: str) -> None:
    """Request cooperative cancellation for one pipeline step.

    Called by: `runtime.control.actions`.
    """
    jobs = require_run_jobs(context, command_run_id)
    context.runtime_store("run cancel").request_cancellation("run", command_run_id)
    for job in jobs:
        cancel_job(context, job)
    context.output(f"cancel requested for step {command_run_id}")


def kill_run(context: CommandContext, command_run_id: str) -> None:
    """Hard-kill jobs associated with one pipeline step.

    Called by: `runtime.control.actions`.
    """
    for job in require_run_jobs(context, command_run_id):
        kill_job(context, job)
    context.output(f"killed step {command_run_id}")


def pause_run(context: CommandContext, command_run_id: str, *, hard: bool, publish_signal: bool = True) -> None:
    """Pause jobs associated with one pipeline step.

    Called by: `runtime.control.actions`.
    """
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
    """Resume or inspect queued actions for one pipeline step.

    Called by: `runtime.control.actions`.
    """
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
    """Stop jobs associated with one pipeline step.

    Called by: `runtime.control.actions`.
    """
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
    """Return jobs associated with a run or raise a clear error.

    Called by: run-level control operations.
    """
    jobs = context.runtime_store("run jobs").jobs_for_run(command_run_id)
    if not jobs:
        raise ValueError(f"unknown or inactive step: {command_run_id}")
    return jobs


def require_pipeline_id(context: CommandContext, pipeline_id: str) -> str:
    """Validate that a pipeline exists and return its ID.

    Called by: pipeline-level control operations.
    """
    runtime = context.runtime_store("pipeline")
    if pipeline_id not in {str(row["pipeline_id"]) for row in runtime.pipelines(active_only=False)}:
        raise ValueError(f"unknown pipeline: {pipeline_id}")
    return pipeline_id
