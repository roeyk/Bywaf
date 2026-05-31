"""Runner facade and foreground pipeline execution.

Provides Runner, command-line execution routing, foreground pipeline execution,
framework selector handling, and stage execution orchestration. Stage context
preparation lives in runner.context; background job lifecycle publication and
child-process entry points live in runner.jobs.

Used by:
- CLI, REPL, and API layers: execute command text and pipelines.
- plugins and tests: coordinate event flow, jobs, artifacts, and runtime state."""


from __future__ import annotations

import argparse
import multiprocessing as mp
import os
from pathlib import Path

from ..command.parser import CommandInvocation, Pipeline, parse_pipeline
from .context import StageRun
from .context import ensure_run_var_snapshot
from .context import is_management_pipeline
from .context import new_run_id
from .context import prepare_stage_runs
from .jobs import JobLifecycle, should_run_stage_processes
from .runtime_events import attach_cursor_event_id
from .runtime_events import pipeline_exists
from .runtime_events import publish_runtime_name
from .stages import execute_stage, run_stage_process
from ..db import EventStore, Subscription
from ..event import Event
from ..registry import PluginRegistry
from ..stores import EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol


class Runner:
    """Execute parsed commandlet pipelines against an EventStore."""

    def __init__(
        self,
        db: EventStore,
        registry: PluginRegistry,
        *,
        job_id: int | None = None,
        project: object | None = None,
    ):
        self.db = db
        self.registry = registry
        self.job_id = job_id
        self.project = project
        self.session_service_job_ids: set[int] = set()
        self.enabled_session_triggers: set[str] = set()
        self.fired_session_trigger_events: set[tuple[str, int]] = set()
        self.trigger_event_cursors: dict[str, int] = {}

    @property
    def events(self) -> EventStoreProtocol:
        """Return the active event/audit store."""
        return self.db

    @property
    def runtime(self) -> RuntimeStoreProtocol:
        """Return the active runtime metadata store."""
        return self.db

    @property
    def maintenance(self) -> MaintenanceStoreProtocol:
        """Return the active maintenance store."""
        return self.db

    def execute(self, command_line: str) -> list[Event]:
        """Run a command line immediately or start it as a background job."""
        pipeline = parse_pipeline(
            command_line,
            varstore=self.registry.varstore,
            command_resolver=self.registry.resolve_commandlet_name,
            command_scope_resolver=self.registry.variable_scope,
        )
        match pipeline:
            case Pipeline(background=True):
                return [self.start_background(command_line, pipeline=pipeline)]
            case Pipeline(commands=commands, display_name=display_name):
                if is_management_pipeline(commands):
                    return self.run_pipeline(commands, pipeline_name=display_name)
                return self.execute_foreground_job(command_line, commands, pipeline_name=display_name)

    def execute_foreground_job(
        self,
        command_line: str,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_name: str | None = None,
    ) -> list[Event]:
        """Run a foreground pipeline through the same job lifecycle.

        Foreground work still gets a job row so `jobs`, audit history, and
        cancellation/review tooling see the same lifecycle shape for foreground
        and background executions.
        """
        pid = os.getpid()
        lifecycle = JobLifecycle.create(self.db, command_line, pid)
        if not lifecycle.claim(pid):
            raise RuntimeError(f"could not claim foreground job {lifecycle.job_id}")
        lifecycle.start(pid)
        previous_job_id = self.job_id
        self.job_id = lifecycle.job_id
        try:
            # Temporarily attach this runner to the foreground job so all stage
            # events inherit the job id while preserving any outer job context.
            events = self.run_pipeline(commands, pipeline_name=pipeline_name)
        except Exception as exc:
            lifecycle.fail(str(exc))
            raise
        finally:
            self.job_id = previous_job_id
        lifecycle.finish()
        return events

    def run_pipeline(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
        stages: tuple[StageRun, ...] | None = None,
        pipeline_name: str | None = None,
    ) -> list[Event]:
        """Run all stages in-process and return produced events.

        Foreground pipelines pass events from one stage directly into the next,
        while every yielded payload is also persisted to SQLite with pipeline
        and pipeline-step scope IDs.
        """
        pipeline_id = pipeline_id or new_run_id("pipeline")
        if pipeline_name:
            publish_runtime_name(self.db, "pipeline", pipeline_id, pipeline_name, pipeline_id=pipeline_id)
        stages = stages or prepare_stage_runs(commands)
        input_events: list[Event] = []
        produced: list[Event] = []
        for stage in stages:
            # Foreground pipelines are stream-like: each stage receives only the
            # visible output of the previous stage, while all emitted events are
            # still persisted for audit and later report queries.
            result = execute_stage(
                self.db,
                self.registry,
                stage,
                pipeline_id=pipeline_id,
                job_id=self.job_id,
                input_events=input_events,
                replace_db=self.replace_db,
                runner=self,
            )
            input_events = result.events
            produced.extend(result.events)
            if result.stopped:
                self.db.publish(
                    "pipeline.stopped",
                    {
                        "pipeline_id": pipeline_id,
                        "reason": result.stop_reason,
                        "command_run_id": stage.command_run_id,
                        "job_id": self.job_id,
                    },
                    "framework",
                    pipeline_id=pipeline_id,
                    command_run_id=stage.command_run_id,
                    parent_command_run_id=stage.parent_command_run_id,
                )
                break
        return produced

    def replace_db(self, db: EventStore) -> None:
        """Replace the active database after an in-process management command."""
        self.db = db

    def run_pipeline_processes(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
        stages: tuple[StageRun, ...] | None = None,
    ) -> None:
        """Run each stage in its own process for stage-level background jobs.

        This is used for background pipelines where each pipeline step should
        have an independent process boundary.  Runtime variables are snapshotted
        before child startup so later `set` changes do not silently alter a job
        already in flight.
        """
        pipeline_id = pipeline_id or new_run_id("pipeline")
        stages = stages or prepare_stage_runs(commands)
        processes: list[mp.Process] = []
        for stage in stages:
            # Child processes do not share the parent registry state, so record
            # the exact variables for this stage before the child reconstructs
            # its execution context from the database.
            ensure_run_var_snapshot(
                self.db,
                self.registry.varstore,
                job_id=self.job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                commandlet=self.registry.variable_scope(stage.invocation.name),
            )
            process = mp.Process(
                target=run_stage_process,
                args=(
                    str(self.db.path),
                    self.db.passphrase,
                    self.job_id,
                    stage.invocation.name,
                    stage.invocation.args,
                    pipeline_id,
                    stage.command_run_id,
                    stage.parent_command_run_id,
                    stage.invocation.background,
                    stage.invocation.from_step,
                    stage.invocation.from_pipeline,
                    stage.invocation.from_job,
                    stage.invocation.from_topic,
                    stage.invocation.replay_after_id,
                    stage.invocation.note,
                    stage.invocation.display_name,
                    stage.invocation.variable_expansions,
                    stage.invocation.expanded_text,
                    stage.invocation.plan_only,
                    stage.invocation.approved,
                ),
                daemon=False,
            )
            process.start()
            processes.append(process)
        # Wait for every stage process here because the containing job process
        # owns the overall lifecycle and should not mark the job complete until
        # all of its stage children have exited.
        for process in processes:
            process.join()

    def start_background(self, command_line: str, *, pipeline: Pipeline | None = None) -> Event:
        """Start an entire command line in a child process and record a job.

        The REPL calls this for commands ending in `&`.  The parent records the
        request event and process id; the child process owns stage execution and
        final job lifecycle updates.
        """
        foreground = command_line.strip()
        pipeline = pipeline or parse_pipeline(
            foreground,
            varstore=self.registry.varstore,
            command_resolver=self.registry.resolve_commandlet_name,
            command_scope_resolver=self.registry.variable_scope,
        )
        pipeline_id = new_run_id("pipeline")
        if pipeline.display_name:
            publish_runtime_name(self.db, "pipeline", pipeline_id, pipeline.display_name, pipeline_id=pipeline_id)
        stages = prepare_stage_runs(pipeline.commands)
        lifecycle = JobLifecycle.create(self.db, foreground, None)
        for stage in stages:
            # Snapshot stage variables before the background process starts for
            # the same reason as `run_pipeline_processes`: background work must
            # be reproducible even if the operator changes variables later.
            ensure_run_var_snapshot(
                self.db,
                self.registry.varstore,
                job_id=lifecycle.job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                commandlet=self.registry.variable_scope(stage.invocation.name),
            )
        process = mp.Process(
            target=run_background_job,
            args=(str(self.db.path), self.db.passphrase, lifecycle.job_id, foreground, pipeline_id, stages),
            daemon=False,
        )
        process.start()
        # Store the child pid after fork so control commands can signal the job.
        self.db.update_job_pid(lifecycle.job_id, process.pid)
        if lifecycle.request_event is None:
            raise RuntimeError("job request event was not recorded")
        return lifecycle.request_event

    def start_attached_pipeline(
        self,
        pipeline_id: str,
        command_line: str,
        *,
        upstream_run_id: str | None = None,
        since_cursor: str = "beginning",
    ) -> Event:
        """Attach one background commandlet to an existing pipeline.

        Attached stages let an operator continue analysis after a pipeline has
        already produced events.  The new stage reads from a chosen cursor and
        writes back into the same pipeline provenance instead of creating a
        disconnected job.
        """
        if not pipeline_exists(self.db, pipeline_id):
            raise ValueError(f"unknown pipeline: {pipeline_id}")
        after_id = attach_cursor_event_id(self.db, since_cursor)
        parsed = parse_pipeline(
            command_line,
            varstore=self.registry.varstore,
            command_resolver=self.registry.resolve_commandlet_name,
            command_scope_resolver=self.registry.variable_scope,
        )
        if len(parsed.commands) != 1:
            raise ValueError("pipeline attach accepts exactly one commandlet")
        original = parsed.commands[0]
        # Force the attached invocation to be background-scoped and bound to the
        # target pipeline.  Other invocation fields are preserved so selectors,
        # notes, display names, approvals, and variable-expansion audit remain
        # attached to the operator's command.
        invocation = CommandInvocation(
            original.name,
            original.args,
            background=True,
            from_step=upstream_run_id,
            from_pipeline=pipeline_id,
            from_job=original.from_job,
            from_topic=original.from_topic,
            replay_after_id=after_id,
            note=original.note,
            display_name=original.display_name,
            variable_expansions=original.variable_expansions,
            expanded_text=original.expanded_text,
            plan_only=original.plan_only,
            approved=original.approved,
        )
        stage = StageRun(invocation, new_run_id(invocation.name), upstream_run_id)
        lifecycle = JobLifecycle.create(
            self.db,
            f"pipeline attach {pipeline_id} {command_line} step={upstream_run_id or ''} since={since_cursor}".strip(),
            None,
        )
        ensure_run_var_snapshot(
            self.db,
            self.registry.varstore,
            job_id=lifecycle.job_id,
            pipeline_id=pipeline_id,
            command_run_id=stage.command_run_id,
            commandlet=self.registry.variable_scope(invocation.name),
        )
        # Publish an explicit attachment event before the child starts.  If the
        # child fails early, audit/history still shows that the operator
        # requested a continuation stage and which cursor it would have used.
        self.db.publish(
            "pipeline.attached",
            {
                "job_id": lifecycle.job_id,
                "pipeline_id": pipeline_id,
                "command": command_line,
                "command_run_id": stage.command_run_id,
                "parent_command_run_id": upstream_run_id,
                "since": since_cursor,
                "after_id": after_id,
            },
            "runner",
            pipeline_id=pipeline_id,
            command_run_id=stage.command_run_id,
            parent_command_run_id=upstream_run_id,
        )
        process = mp.Process(
            target=run_attached_pipeline_job,
            args=(str(self.db.path), self.db.passphrase, lifecycle.job_id, command_line, pipeline_id, stage),
            daemon=False,
        )
        process.start()
        # Store the pid for ordinary runtime controls (`cancel`, `kill`, etc.).
        self.db.update_job_pid(lifecycle.job_id, process.pid)
        if lifecycle.request_event is None:
            raise RuntimeError("job request event was not recorded")
        return lifecycle.request_event

    def subscribe_once(self, topics: tuple[str, ...], after_id: int = 0) -> list[Event]:
        """Small convenience wrapper used by tests and simple callers."""
        return self.db.fetch(Subscription(topics=topics, after_id=after_id))


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
        # line. Stage snapshots carry variable values captured by the parent.
        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        pipeline = parse_pipeline(
            command_line,
            command_resolver=runner.registry.resolve_commandlet_name,
            command_scope_resolver=runner.registry.variable_scope,
        )
        if should_run_stage_processes(pipeline.commands):
            runner.run_pipeline_processes(pipeline.commands, pipeline_id=pipeline_id, stages=stages)
        else:
            runner.run_pipeline(pipeline.commands, pipeline_id=pipeline_id, stages=stages)
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
    stage: StageRun,
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
        # Attached stages inherit the parent pipeline id but execute in their
        # own job process so long-running fan-out work can be tracked.
        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        runner.run_pipeline((stage.invocation,), pipeline_id=pipeline_id, stages=(stage,))
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()




def add_runner_arguments(parser: argparse.ArgumentParser) -> None:
    """Add `bywaf exec ...` OS command arguments without requiring quotes for simple cases."""
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command line to run, e.g. hostscanner 127.0.0.1",
    )
