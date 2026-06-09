"""Background runner child-process entry points.

Used by:
- `Runner.start_background()`: forks `run_background_job`.
- `Runner.start_attached_pipeline()`: forks `run_attached_pipeline_job`.
"""

from __future__ import annotations

import multiprocessing as mp
from dataclasses import dataclass
from pathlib import Path

from ..command.parser import parse_pipeline
from ..db import EventStore
from ..event import Event
from ..registry import PluginRegistry
from .context import StageRun
from .jobs import JobLifecycle, should_run_stage_processes
from .pipeline_steps import execute_pipeline_steps, run_pipeline_step_processes


@dataclass(slots=True)
class BackgroundRunner:
    """Minimal runner object used inside background child processes.

    `execute_pipeline_steps()` and `run_pipeline_step_processes()` need a small
    runner-shaped object: database, registry, job id, and `replace_db()`.  Using
    this internal object keeps background entry points from importing the public
    `Runner` facade back from `runner.core`, which would create a core/background
    import cycle.
    """

    db: EventStore
    registry: PluginRegistry
    job_id: int | None

    def replace_db(self, db: EventStore) -> None:
        """Replace the active database after an in-process management command."""
        self.db = db


def run_background_job(
    db_path: str,
    db_passphrase: str | None,
    job_id: int,
    command_line: str,
    pipeline_id: str,
    stages: tuple[StageRun, ...],
) -> None:
    """Child-process entry point for a background pipeline.

    The child reopens the database and rediscovers bundled plugins instead of
    inheriting live connection/plugin objects from the parent process.
    """
    try:
        db = EventStore(Path(db_path), passphrase=db_passphrase)
        pid = mp.current_process().pid
        lifecycle = JobLifecycle(db, job_id, command_line)
        if not lifecycle.claim(pid):
            return
    except Exception:
        # The parent may have exited or removed a temporary database before the
        # child starts. There is nowhere reliable to record that failure, so the
        # child exits quietly instead of printing a multiprocessing traceback.
        return
    try:
        lifecycle.start(pid)
        # The child process rebuilds parser/registry state from the command
        # line. Step snapshots carry variable values captured by the parent.
        runner = BackgroundRunner(db, PluginRegistry.discover(), job_id)
        pipeline = parse_pipeline(
            command_line,
            command_resolver=runner.registry.resolve_commandlet_name,
            command_scope_resolver=runner.registry.variable_scope,
        )
        for invocation in pipeline.commands:
            if not runner.registry.has_commandlet(invocation.name):
                raise KeyError(f"unknown commandlet: {invocation.name}")
        if should_run_stage_processes(pipeline.commands):
            run_pipeline_step_processes(runner, stages, pipeline_id=pipeline_id)
        else:
            _run_pipeline(runner, stages, pipeline_id=pipeline_id)
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()


def run_attached_pipeline_job(
    db_path: str,
    db_passphrase: str | None,
    job_id: int,
    command_line: str,
    pipeline_id: str,
    step_run: StageRun,
) -> None:
    """Child-process entry point for a commandlet attached to a live pipeline."""
    try:
        db = EventStore(Path(db_path), passphrase=db_passphrase)
        pid = mp.current_process().pid
        lifecycle = JobLifecycle(db, job_id, command_line)
        if not lifecycle.claim(pid):
            return
    except Exception:
        return
    try:
        lifecycle.start(pid)
        # Attached steps inherit the parent pipeline id but execute in their
        # own job process so long-running fan-out work can be tracked.
        runner = BackgroundRunner(db, PluginRegistry.discover(), job_id)
        _run_pipeline(runner, (step_run,), pipeline_id=pipeline_id)
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()


def _run_pipeline(
    runner: BackgroundRunner,
    stages: tuple[StageRun, ...],
    *,
    pipeline_id: str,
) -> list[Event]:
    """Run background pipeline stages through the shared step executor."""
    return execute_pipeline_steps(runner, stages, pipeline_id=pipeline_id)
