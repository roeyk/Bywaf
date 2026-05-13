"""Command parser, foreground execution, and background process runner."""

from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path

from .db import EventStore, Subscription
from .events import Event
from .plugin import CommandContext
from .registry import PluginRegistry
from .utils import split_pipeline


@dataclass(frozen=True, slots=True)
class CommandInvocation:
    """Parsed commandlet invocation plus framework-owned execution selectors."""

    name: str
    args: list[str]
    background: bool = False
    from_run: str | None = None
    from_pipeline: str | None = None
    from_topic: str | None = None


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A sequence of commandlets connected by pipe syntax."""

    commands: tuple[CommandInvocation, ...]
    background: bool = False


def parse_invocation(text: str) -> CommandInvocation:
    """Parse one commandlet expression.

    This function strips Bywaf framework selectors such as `--from-run` before
    plugin argparse sees the remaining plugin-owned arguments.
    """
    tokens = shlex.split(text)
    background = False
    if tokens:
        tokens, background = peel_background_marker(tokens)
    if not tokens:
        raise ValueError("empty command")
    name, *args = tokens
    args, selectors = peel_context_selectors(args)
    return CommandInvocation(name=name, args=args, background=background, **selectors)


def parse_pipeline(command_line: str) -> Pipeline:
    """Parse a full pipeline and detect foreground/background execution."""
    parts, background = split_pipeline(command_line)
    if not parts:
        raise ValueError("empty pipeline")
    commands = list(parse_invocation(part) for part in parts)
    if background and commands:
        last = commands[-1]
        commands[-1] = CommandInvocation(last.name, last.args, background=True)
    return Pipeline(tuple(commands), any(command.background for command in commands))


@dataclass(frozen=True, slots=True)
class StageRun:
    """Execution identity assigned to one pipeline stage."""

    invocation: CommandInvocation
    command_run_id: str
    parent_command_run_id: str | None


class Runner:
    """Execute parsed commandlet pipelines against an EventStore."""

    def __init__(self, db: EventStore, registry: PluginRegistry, *, job_id: int | None = None):
        self.db = db
        self.registry = registry
        self.job_id = job_id

    def execute(self, command_line: str) -> list[Event]:
        """Run a command line immediately or start it as a background job."""
        pipeline = parse_pipeline(command_line)
        match pipeline:
            case Pipeline(background=True):
                return [self.start_background(command_line)]
            case Pipeline(commands=commands):
                if is_management_pipeline(commands):
                    return self.run_pipeline(commands)
                return self.execute_foreground_job(command_line, commands)

    def execute_foreground_job(
        self,
        command_line: str,
        commands: tuple[CommandInvocation, ...],
    ) -> list[Event]:
        """Run a foreground pipeline through the same job lifecycle."""
        job_id = self.db.record_job(command_line.strip(), os.getpid(), "queued")
        self.db.publish("job.requested", {"job_id": job_id, "command": command_line.strip()}, "runner")
        if not self.db.claim_job(job_id, os.getpid()):
            self.db.publish("job.claim.denied", {"job_id": job_id, "pid": os.getpid()}, "runner")
            raise RuntimeError(f"could not claim foreground job {job_id}")
        self.db.publish("job.claimed", {"job_id": job_id, "pid": os.getpid()}, "runner")
        self.db.update_job_status(job_id, "running")
        self.db.publish("job.started", {"job_id": job_id, "pid": os.getpid(), "command": command_line.strip()}, "runner")
        previous_job_id = self.job_id
        self.job_id = job_id
        try:
            events = self.run_pipeline(commands)
        except Exception as exc:
            self.db.publish("job.failed", {"job_id": job_id, "error": str(exc)}, "runner")
            self.db.finish_job(job_id, "failed")
            raise
        finally:
            self.job_id = previous_job_id
        self.db.publish("job.finished", {"job_id": job_id, "command": command_line.strip()}, "runner")
        self.db.finish_job(job_id, "finished")
        return events

    def run_pipeline(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
    ) -> list[Event]:
        """Run all stages in-process and return produced events.

        Foreground pipelines pass events from one stage directly into the next,
        while every yielded payload is also persisted to SQLite with pipeline
        and command-run scope IDs.
        """
        pipeline_id = pipeline_id or new_run_id("pipeline")
        input_events: list[Event] = []
        produced: list[Event] = []
        for stage in prepare_stage_runs(commands):
            invocation = stage.invocation
            plugin = self.registry.get(invocation.name)
            selected_input_events = select_input_events(self.db, invocation, input_events)
            input_high_watermark = max((event.id or 0 for event in selected_input_events), default=0)
            context = CommandContext(
                self.db,
                source=plugin.spec.name,
                _varstore=self.registry.varstore,
                metadata={
                    "pipeline_id": pipeline_id,
                    "command_run_id": stage.command_run_id,
                    "parent_command_run_id": stage.parent_command_run_id,
                    "input_high_watermark": input_high_watermark,
                    "background": invocation.background,
                    "from_run": invocation.from_run,
                    "from_pipeline": invocation.from_pipeline,
                    "from_topic": invocation.from_topic,
                    "replace_db": self.replace_db,
                    "job_id": self.job_id,
                },
            )
            context.raise_if_cancelled()
            topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
            output_payloads = plugin.run(context, invocation.args, selected_input_events)
            input_events = [
                # The framework stores all plugin output under the commandlet's
                # first declared topic. Plugins that do not declare topics use
                # their command name as a conservative fallback.
                self.db.publish(
                    topic,
                    payload,
                    plugin.spec.name,
                    pipeline_id=pipeline_id,
                    command_run_id=stage.command_run_id,
                    parent_command_run_id=stage.parent_command_run_id,
                )
                for payload in output_payloads
            ]
            produced.extend(input_events)
        return produced

    def replace_db(self, db: EventStore) -> None:
        """Replace the active database after an in-process management command."""
        self.db = db

    def run_pipeline_processes(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
    ) -> None:
        """Run each stage in its own process for stage-level background jobs."""
        pipeline_id = pipeline_id or new_run_id("pipeline")
        processes: list[mp.Process] = []
        for stage in prepare_stage_runs(commands):
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
                    stage.invocation.from_run,
                    stage.invocation.from_pipeline,
                    stage.invocation.from_topic,
                ),
                daemon=False,
            )
            process.start()
            processes.append(process)
        for process in processes:
            process.join()

    def start_background(self, command_line: str) -> Event:
        """Start an entire command line in a child process and record a job."""
        foreground = command_line.strip()
        job_id = self.db.record_job(foreground, None, "queued")
        requested = self.db.publish(
            "job.requested",
            {"job_id": job_id, "command": foreground},
            "runner",
        )
        process = mp.Process(
            target=run_background_job,
            args=(str(self.db.path), self.db.passphrase, job_id, foreground),
            daemon=False,
        )
        process.start()
        self.db.update_job_pid(job_id, process.pid)
        return requested

    def subscribe_once(self, topics: tuple[str, ...], after_id: int = 0) -> list[Event]:
        """Small convenience wrapper used by tests and simple callers."""
        return self.db.fetch(Subscription(topics=topics, after_id=after_id))


def run_background_job(
    db_path: str,
    db_passphrase: str | None,
    job_id: int,
    command_line: str,
) -> None:
    """Child-process entry point for a background pipeline.

    The child reopens the database and rediscovers bundled plugins instead of
    inheriting live connection/plugin objects from the parent process.
    """
    db = EventStore(Path(db_path), passphrase=db_passphrase)
    pid = mp.current_process().pid
    if not db.claim_job(job_id, pid):
        db.publish("job.claim.denied", {"job_id": job_id, "pid": pid}, "runner")
        return
    db.publish("job.claimed", {"job_id": job_id, "pid": pid}, "runner")
    try:
        db.update_job_status(job_id, "running")
        db.publish("job.started", {"job_id": job_id, "pid": pid, "command": command_line}, "runner")
        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        pipeline = parse_pipeline(command_line)
        if pipeline.background:
            runner.run_pipeline_processes(pipeline.commands)
        else:
            runner.run_pipeline(pipeline.commands)
    except Exception as exc:  # pragma: no cover - defensive child-process boundary
        db.publish("job.failed", {"job_id": job_id, "error": str(exc)}, "runner")
        db.finish_job(job_id, "failed")
        raise
    else:
        db.publish("job.finished", {"job_id": job_id, "command": command_line}, "runner")
        db.finish_job(job_id, "finished")


def add_runner_arguments(parser: argparse.ArgumentParser) -> None:
    """Add `bywaf run ...` arguments without requiring quotes for simple cases."""
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command line to run, e.g. hostscanner 127.0.0.1",
    )


def new_run_id(prefix: str) -> str:
    """Return a readable unique ID suitable for DB scope fields."""
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    return f"{safe_prefix}-{uuid.uuid4().hex}"


def peel_background_marker(tokens: list[str]) -> tuple[list[str], bool]:
    """Remove a trailing shell-style `&` marker from a token list."""
    last = tokens[-1]
    if last == "&":
        return tokens[:-1], True
    if last.endswith("&"):
        stripped = last[:-1]
        if stripped:
            return [*tokens[:-1], stripped], True
        return tokens[:-1], True
    return tokens, False


def peel_context_selectors(args: list[str]) -> tuple[list[str], dict[str, str | None]]:
    """Remove framework-owned selector flags from plugin arguments."""
    selectors: dict[str, str | None] = {"from_run": None, "from_pipeline": None, "from_topic": None}
    cleaned: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        match token:
            case "--from-run" | "--from":
                selectors["from_run"] = require_selector_value(args, index, token)
                index += 2
            case "--from-pipeline" | "--pipeline":
                selectors["from_pipeline"] = require_selector_value(args, index, token)
                index += 2
            case "--from-topic" | "--topic":
                selectors["from_topic"] = require_selector_value(args, index, token)
                index += 2
            case _:
                cleaned.append(token)
                index += 1
    return cleaned, selectors


def require_selector_value(args: list[str], index: int, token: str) -> str:
    """Return the value after a selector flag or raise a friendly parse error."""
    try:
        return args[index + 1]
    except IndexError as exc:
        raise ValueError(f"{token} requires a value") from exc


def select_input_events(
    db: EventStore,
    invocation: CommandInvocation,
    fallback_events: list[Event],
) -> list[Event]:
    """Choose pipeline input events or DB-selected events for one invocation."""
    if not any((invocation.from_run, invocation.from_pipeline, invocation.from_topic)):
        return fallback_events
    return db.events_matching(
        command_run_id=invocation.from_run,
        pipeline_id=invocation.from_pipeline,
        topic=invocation.from_topic,
    )


def prepare_stage_runs(commands: tuple[CommandInvocation, ...]) -> tuple[StageRun, ...]:
    """Assign stable run IDs and upstream parent IDs to pipeline stages."""
    stages: list[StageRun] = []
    parent_id: str | None = None
    for invocation in commands:
        command_run_id = new_run_id(invocation.name)
        stages.append(StageRun(invocation, command_run_id, parent_id))
        parent_id = command_run_id
    return tuple(stages)


def is_management_pipeline(commands: tuple[CommandInvocation, ...]) -> bool:
    """Return True for foreground management commands that should run directly."""
    return len(commands) == 1 and commands[0].name in {"db", "job"}


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
    from_run: str | None,
    from_pipeline: str | None,
    from_topic: str | None,
) -> None:
    """Child-process entry point for one background pipeline stage."""
    db = EventStore(Path(db_path), passphrase=db_passphrase)
    registry = PluginRegistry.discover()
    plugin = registry.get(name)
    context = CommandContext(
        db,
        source=plugin.spec.name,
        _varstore=registry.varstore,
        metadata={
            "pipeline_id": pipeline_id,
            "command_run_id": command_run_id,
            "parent_command_run_id": parent_command_run_id,
            "input_high_watermark": 0,
            "background": background,
            "from_run": from_run,
            "from_pipeline": from_pipeline,
            "from_topic": from_topic,
            "job_id": job_id,
        },
    )
    context.raise_if_cancelled()
    topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
    invocation = CommandInvocation(
        name,
        args,
        background=background,
        from_run=from_run,
        from_pipeline=from_pipeline,
        from_topic=from_topic,
    )
    input_events = select_input_events(db, invocation, [])
    for payload in plugin.run(context, args, input_events):
        db.publish(
            topic,
            payload,
            plugin.spec.name,
            pipeline_id=pipeline_id,
            command_run_id=command_run_id,
            parent_command_run_id=parent_command_run_id,
        )
