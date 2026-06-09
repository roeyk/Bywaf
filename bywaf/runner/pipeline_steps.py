"""Pipeline-step orchestration helpers for the runner facade.

Used by: `runner.core.Runner.run_pipeline()` and
`Runner.run_pipeline_processes()` to keep the facade focused on command
routing, job lifecycle, and process startup.
"""

from __future__ import annotations

import multiprocessing as mp
from typing import TYPE_CHECKING

from ..event import Event
from .context import StageRun, ensure_run_var_snapshot
from .stages import execute_stage, run_stage_process

if TYPE_CHECKING:
    from .core import Runner


def execute_pipeline_steps(
    runner: Runner,
    step_runs: tuple[StageRun, ...],
    *,
    pipeline_id: str,
) -> list[Event]:
    """Run in-process pipeline steps and return the events visible downstream."""
    input_events: list[Event] = []
    produced: list[Event] = []
    for step_run in step_runs:
        # Foreground pipelines are stream-like: each step receives only the
        # visible output of the previous step, while all emitted events are
        # still persisted for audit and later report queries.
        result = execute_stage(
            runner.db,
            runner.registry,
            step_run,
            pipeline_id=pipeline_id,
            job_id=runner.job_id,
            input_events=input_events,
            replace_db=runner.replace_db,
            runner=runner,
        )
        input_events = result.events
        produced.extend(result.events)
        if result.stopped:
            publish_pipeline_stopped(runner, step_run, pipeline_id=pipeline_id, reason=result.stop_reason)
            break
    return produced


def publish_pipeline_stopped(
    runner: Runner,
    step_run: StageRun,
    *,
    pipeline_id: str,
    reason: str,
) -> None:
    """Record an intentional pipeline stop caused by one pipeline step."""
    runner.db.publish(
        "pipeline.stopped",
        {
            "pipeline_id": pipeline_id,
            "reason": reason,
            "command_run_id": step_run.command_run_id,
            "job_id": runner.job_id,
        },
        "framework",
        pipeline_id=pipeline_id,
        command_run_id=step_run.command_run_id,
        parent_command_run_id=step_run.parent_command_run_id,
    )


def run_pipeline_step_processes(
    runner: Runner,
    step_runs: tuple[StageRun, ...],
    *,
    pipeline_id: str,
) -> None:
    """Run each pipeline step in its own child process and wait for completion."""
    processes: list[mp.Process] = []
    for step_run in step_runs:
        # Child processes do not share the parent registry state, so record the
        # exact variables for this step before the child reconstructs its
        # execution context from the database.
        snapshot_step_variables(runner, step_run, job_id=runner.job_id, pipeline_id=pipeline_id)
        process = mp.Process(
            target=run_stage_process,
            args=stage_process_args(runner, step_run, pipeline_id=pipeline_id),
            daemon=False,
        )
        process.start()
        processes.append(process)
    # Wait for every step process here because the containing job process owns
    # the overall lifecycle and should not mark the job complete until all of
    # its step children have exited.
    for process in processes:
        process.join()


def snapshot_step_variables(
    runner: Runner,
    step_run: StageRun,
    *,
    job_id: int | None,
    pipeline_id: str,
) -> None:
    """Persist variable values visible to one pipeline step before execution."""
    ensure_run_var_snapshot(
        runner.db,
        runner.registry.varstore,
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=step_run.command_run_id,
        commandlet=runner.registry.variable_scope(step_run.invocation.name),
    )


def stage_process_args(
    runner: Runner,
    step_run: StageRun,
    *,
    pipeline_id: str,
) -> tuple[object, ...]:
    """Return `run_stage_process()` arguments for one child step process."""
    return (
        str(runner.db.path),
        runner.db.passphrase,
        runner.job_id,
        step_run.invocation.name,
        step_run.invocation.args,
        pipeline_id,
        step_run.command_run_id,
        step_run.parent_command_run_id,
        step_run.invocation.background,
        step_run.invocation.from_step,
        step_run.invocation.from_pipeline,
        step_run.invocation.from_job,
        step_run.invocation.from_topic,
        step_run.invocation.replay_after_id,
        step_run.invocation.note,
        step_run.invocation.display_name,
        step_run.invocation.variable_expansions,
        step_run.invocation.expanded_text,
        step_run.invocation.plan_only,
        step_run.invocation.approved,
    )
