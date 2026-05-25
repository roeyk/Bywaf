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
from dataclasses import dataclass
from pathlib import Path

from ..command_parser import CommandInvocation, Pipeline, parse_pipeline
from .at_files import expand_at_file_args
from .context import StageRun
from .context import build_context
from .context import ensure_run_var_snapshot
from .context import is_management_pipeline
from .context import new_run_id
from .context import prepare_stage_runs
from .context import select_input_events
from .jobs import JobLifecycle, run_attached_pipeline_job, run_background_job
from .plans import handle_plan_if_needed
from .runtime_events import attach_cursor_event_id
from .runtime_events import pipeline_exists
from .runtime_events import publish_note_if_present
from .runtime_events import publish_runtime_name
from .runtime_events import publish_variable_expansion
from ..db import EventStore, Subscription
from ..events import Event
from ..plugin import CommandContext
from ..registry import PluginRegistry
from ..secrets import REDACTED_VALUE, fingerprint_secret, load_or_create_fingerprint_key
from ..stores import EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol


@dataclass(frozen=True, slots=True)
class StageResult:
    """Events produced by one executed pipeline stage."""

    events: list[Event]


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
        """Run a foreground pipeline through the same job lifecycle."""
        pid = os.getpid()
        lifecycle = JobLifecycle.create(self.db, command_line, pid)
        if not lifecycle.claim(pid):
            raise RuntimeError(f"could not claim foreground job {lifecycle.job_id}")
        lifecycle.start(pid)
        previous_job_id = self.job_id
        self.job_id = lifecycle.job_id
        try:
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
        """Run each stage in its own process for stage-level background jobs."""
        pipeline_id = pipeline_id or new_run_id("pipeline")
        stages = stages or prepare_stage_runs(commands)
        processes: list[mp.Process] = []
        for stage in stages:
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
                    stage.invocation.from_topic,
                    stage.invocation.replay_after_id,
                    stage.invocation.note,
                    stage.invocation.display_name,
                    stage.invocation.variable_expansions,
                    stage.invocation.plan_only,
                    stage.invocation.approved,
                ),
                daemon=False,
            )
            process.start()
            processes.append(process)
        for process in processes:
            process.join()

    def start_background(self, command_line: str, *, pipeline: Pipeline | None = None) -> Event:
        """Start an entire command line in a child process and record a job."""
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
        """Attach one background commandlet to an existing pipeline."""
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
        invocation = CommandInvocation(
            original.name,
            original.args,
            background=True,
            from_step=upstream_run_id,
            from_pipeline=pipeline_id,
            from_topic=original.from_topic,
            replay_after_id=after_id,
            note=original.note,
            display_name=original.display_name,
            variable_expansions=original.variable_expansions,
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
        self.db.update_job_pid(lifecycle.job_id, process.pid)
        if lifecycle.request_event is None:
            raise RuntimeError("job request event was not recorded")
        return lifecycle.request_event

    def subscribe_once(self, topics: tuple[str, ...], after_id: int = 0) -> list[Event]:
        """Small convenience wrapper used by tests and simple callers."""
        return self.db.fetch(Subscription(topics=topics, after_id=after_id))




def add_runner_arguments(parser: argparse.ArgumentParser) -> None:
    """Add `bywaf exec ...` OS command arguments without requiring quotes for simple cases."""
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command line to run, e.g. hostscanner 127.0.0.1",
    )


def execute_stage(
    db: EventStore,
    registry: PluginRegistry,
    stage: StageRun,
    *,
    pipeline_id: str,
    job_id: int | None,
    input_events: list[Event],
    replace_db=None,
    runner=None,
) -> StageResult:
    """Execute one pipeline stage and persist yielded payloads as events."""
    invocation = stage.invocation
    plugin = registry.get(invocation.name)
    selected_input_events = select_input_events(db, invocation, input_events)
    input_high_watermark = max(
        (event.id or 0 for event in selected_input_events),
        default=invocation.replay_after_id,
    )
    context = build_context(
        db,
        registry,
        stage,
        pipeline_id=pipeline_id,
        job_id=job_id,
        input_high_watermark=input_high_watermark,
        replace_db=replace_db,
        runner=runner,
    )
    context.raise_if_cancelled()
    stage_start_event_id = db.latest_event_id()
    publish_command_run_lifecycle(context, "started")
    publish_note_if_present(db, context, invocation.note)
    try:
        if invocation.display_name:
            publish_runtime_name(
                db,
                "run",
                stage.command_run_id,
                invocation.display_name,
                job_id=job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                parent_command_run_id=stage.parent_command_run_id,
            )
        publish_variable_expansion(context, invocation.variable_expansions)
        expanded_args = expand_at_file_args(context, invocation.args)
        planned_args = handle_plan_if_needed(context, plugin, expanded_args, selected_input_events, invocation)
        if planned_args is None:
            publish_command_run_lifecycle(context, "completed", emitted=0, skipped=True)
            return StageResult([])
        expanded_args = normalize_valued_option_args(plugin, planned_args)
        publish_command_run_arguments(context, plugin, expanded_args)
        for input_topic in sorted({event.topic for event in selected_input_events}):
            context.audit_capability(f"db.read:{input_topic}")
        topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
        yielded_events = []
        for payload in plugin.run(context, expanded_args, selected_input_events):
            context.audit_capability(f"db.write:{topic}")
            yielded_events.append(db.publish(
                topic,
                payload,
                plugin.spec.name,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                parent_command_run_id=stage.parent_command_run_id,
            ))
        events = pipeline_visible_stage_events(
            db,
            plugin.spec.emits,
            stage.command_run_id,
            after_id=stage_start_event_id,
            yielded_events=yielded_events,
        )
        publish_command_run_lifecycle(context, "completed", emitted=len(events))
        return StageResult(events)
    except Exception as exc:
        publish_command_run_lifecycle(context, "failed", error=str(exc), exception=exc.__class__.__name__)
        raise


def pipeline_visible_stage_events(
    db: EventStore,
    emitted_topics: tuple[str, ...],
    command_run_id: str,
    *,
    after_id: int,
    yielded_events: list[Event],
) -> list[Event]:
    """Return events from this stage that should feed the next pipeline stage."""
    if not emitted_topics:
        return yielded_events
    emitted = set(emitted_topics)
    direct_events = [
        event
        for event in db.events_matching(command_run_id=command_run_id, after_id=after_id, limit=10000)
        if event.topic in emitted
    ]
    by_id: dict[int, Event] = {}
    unsaved: list[Event] = []
    for event in [*yielded_events, *direct_events]:
        if event.id is None:
            unsaved.append(event)
            continue
        by_id[event.id] = event
    return [*unsaved, *[by_id[event_id] for event_id in sorted(by_id)]]


def normalize_valued_option_args(plugin, args: list[str]) -> list[str]:
    """Convert public `name=value` syntax into argparse `--name value` pairs."""
    valued_options = {
        option.name
        for option in plugin.spec.options
        if option.name not in {"listen", "silent"}
    }
    normalized: list[str] = []
    for arg in args:
        if "=" not in arg or arg.startswith("--"):
            normalized.append(arg)
            continue
        key, value = arg.split("=", 1)
        if key not in valued_options:
            normalized.append(arg)
            continue
        normalized.extend((f"--{key}", value))
    return normalized


def publish_command_run_lifecycle(context: CommandContext, status: str, **details: object) -> Event | None:
    """Publish pipeline-step lifecycle events used by finite listeners."""
    if context._db is None:
        return None
    payload = {
        "status": status,
        "commandlet": context.source,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "parent_command_run_id": context.parent_command_run_id,
    }
    payload.update(details)
    return context._db.publish(
        f"command.run.{status}",
        payload,
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_command_run_arguments(context: CommandContext, plugin, args: list[str]) -> Event | None:
    """Publish commandlet arguments after framework expansion/redaction."""
    if context._db is None:
        return None
    redacted_args, secret_args = redact_commandlet_args(context, plugin, args)
    return context._db.publish(
        "command.run.arguments",
        {
            "commandlet": context.source,
            "args": redacted_args,
            "secret_args": secret_args,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "parent_command_run_id": context.parent_command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def redact_commandlet_args(context: CommandContext, plugin, args: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Redact declared secret commandlet options while preserving provenance."""
    secret_options = {option.name.strip().lower().replace("_", "-") for option in plugin.spec.options if option.secret}
    if not secret_options:
        return list(args), []
    redacted: list[str] = []
    secrets: list[dict[str, str]] = []
    pending_secret_option: str | None = None
    for arg in args:
        if pending_secret_option is not None:
            redacted.append(REDACTED_VALUE)
            secrets.append(secret_arg_metadata(context, pending_secret_option, arg))
            pending_secret_option = None
            continue
        option_name, value, style = split_option_arg(arg)
        if option_name is not None and option_name in secret_options:
            if value is None:
                redacted.append(f"--{option_name}")
                pending_secret_option = option_name
                continue
            secrets.append(secret_arg_metadata(context, option_name, value))
            redacted.append(f"--{option_name}={REDACTED_VALUE}" if style == "long-equals" else f"{option_name}={REDACTED_VALUE}")
            continue
        redacted.append(arg)
    return redacted, secrets


def split_option_arg(arg: str) -> tuple[str | None, str | None, str]:
    """Return normalized option name/value/style for long options and key=value."""
    if arg.startswith("--") and "=" in arg:
        key, value = arg[2:].split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "long-equals"
    if arg.startswith("--"):
        return arg[2:].strip().lower().replace("_", "-"), None, "long"
    if "=" in arg:
        key, value = arg.split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "key-equals"
    return None, None, ""


def secret_arg_metadata(context: CommandContext, name: str, value: str) -> dict[str, str]:
    """Return audit-safe metadata for one secret argument value."""
    secret_ref = context._secrets.metadata(value)
    if secret_ref is not None:
        return {"name": secret_ref.name, "option": name, "fingerprint": secret_ref.fingerprint.format()}
    return {
        "name": name,
        "option": name,
        "fingerprint": fingerprint_secret(value, load_or_create_fingerprint_key()).format(),
    }


def run_stage_process(
    db_path: str,
    db_passphrase: str | None,
    job_id: int | None,
    name: str,
    args: list[str],
    pipeline_id: str,
    command_run_id: str,
    parent_command_run_id: str | None,
    background: bool,
    from_step: str | None,
    from_pipeline: str | None,
    from_topic: str | None,
    replay_after_id: int,
    note: str | None,
    display_name: str | None,
    variable_expansions: tuple[str, ...],
    plan_only: bool,
    approved: bool,
) -> None:
    """Child-process entry point for one background pipeline stage."""
    db = EventStore(Path(db_path), passphrase=db_passphrase)
    registry = PluginRegistry.discover()
    stage = StageRun(
        CommandInvocation(
            name,
            args,
            background=background,
            from_step=from_step,
            from_pipeline=from_pipeline,
            from_topic=from_topic,
            replay_after_id=replay_after_id,
            note=note,
            display_name=display_name,
            variable_expansions=variable_expansions,
            plan_only=plan_only,
            approved=approved,
        ),
        command_run_id,
        parent_command_run_id,
    )
    execute_stage(db, registry, stage, pipeline_id=pipeline_id, job_id=job_id, input_events=[])
