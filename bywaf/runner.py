"""Command parser, foreground execution, and background process runner."""

from __future__ import annotations

import argparse
import multiprocessing as mp
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
    name: str
    args: list[str]
    background: bool = False
    from_run: str | None = None
    from_pipeline: str | None = None
    from_topic: str | None = None


@dataclass(frozen=True, slots=True)
class Pipeline:
    commands: tuple[CommandInvocation, ...]
    background: bool = False


def parse_invocation(text: str) -> CommandInvocation:
    tokens = shlex.split(text)
    background = False
    if tokens:
        tokens, background = peel_background_marker(tokens)
    match tokens:
        case []:
            raise ValueError("empty command")
        case [name, *args]:
            args, selectors = peel_context_selectors(args)
            return CommandInvocation(name=name, args=args, background=background, **selectors)


def parse_pipeline(command_line: str) -> Pipeline:
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
    invocation: CommandInvocation
    command_run_id: str
    parent_command_run_id: str | None


class Runner:
    def __init__(self, db: EventStore, registry: PluginRegistry):
        self.db = db
        self.registry = registry

    def execute(self, command_line: str) -> list[Event]:
        pipeline = parse_pipeline(command_line)
        match pipeline:
            case Pipeline(background=True):
                return [self.start_background(command_line)]
            case Pipeline(commands=commands):
                return self.run_pipeline(commands)

    def run_pipeline(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
    ) -> list[Event]:
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
                varstore=self.registry.varstore,
                metadata={
                    "pipeline_id": pipeline_id,
                    "command_run_id": stage.command_run_id,
                    "parent_command_run_id": stage.parent_command_run_id,
                    "input_high_watermark": input_high_watermark,
                    "background": invocation.background,
                    "from_run": invocation.from_run,
                    "from_pipeline": invocation.from_pipeline,
                    "from_topic": invocation.from_topic,
                },
            )
            topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
            output_payloads = plugin.run(context, invocation.args, selected_input_events)
            input_events = [
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

    def run_pipeline_processes(
        self,
        commands: tuple[CommandInvocation, ...],
        *,
        pipeline_id: str | None = None,
    ) -> None:
        pipeline_id = pipeline_id or new_run_id("pipeline")
        processes: list[mp.Process] = []
        for stage in prepare_stage_runs(commands):
            process = mp.Process(
                target=run_stage_process,
                args=(
                    str(self.db.path),
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
        foreground = command_line.strip()
        process = mp.Process(target=run_background_job, args=(str(self.db.path), foreground), daemon=False)
        process.start()
        job_id = self.db.record_job(foreground, process.pid, "running")
        return self.db.publish(
            "job.started",
            {"job_id": job_id, "pid": process.pid, "command": foreground},
            "runner",
        )

    def subscribe_once(self, topics: tuple[str, ...], after_id: int = 0) -> list[Event]:
        return self.db.fetch(Subscription(topics=topics, after_id=after_id))


def run_background_job(db_path: str, command_line: str) -> None:
    db = EventStore(Path(db_path))
    job_id = db.record_job(command_line, None, "child-running")
    try:
        runner = Runner(db, PluginRegistry.discover())
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
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command line to run, e.g. hostscanner 127.0.0.1",
    )


def new_run_id(prefix: str) -> str:
    safe_prefix = "".join(char if char.isalnum() else "-" for char in prefix).strip("-")
    return f"{safe_prefix}-{uuid.uuid4().hex}"


def peel_background_marker(tokens: list[str]) -> tuple[list[str], bool]:
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
    selectors = {"from_run": None, "from_pipeline": None, "from_topic": None}
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
    try:
        return args[index + 1]
    except IndexError as exc:
        raise ValueError(f"{token} requires a value") from exc


def select_input_events(
    db: EventStore,
    invocation: CommandInvocation,
    fallback_events: list[Event],
) -> list[Event]:
    if not any((invocation.from_run, invocation.from_pipeline, invocation.from_topic)):
        return fallback_events
    return db.events_matching(
        command_run_id=invocation.from_run,
        pipeline_id=invocation.from_pipeline,
        topic=invocation.from_topic,
    )


def prepare_stage_runs(commands: tuple[CommandInvocation, ...]) -> tuple[StageRun, ...]:
    stages: list[StageRun] = []
    parent_id: str | None = None
    for invocation in commands:
        command_run_id = new_run_id(invocation.name)
        stages.append(StageRun(invocation, command_run_id, parent_id))
        parent_id = command_run_id
    return tuple(stages)


def run_stage_process(
    db_path: str,
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
    db = EventStore(Path(db_path))
    registry = PluginRegistry.discover()
    plugin = registry.get(name)
    context = CommandContext(
        db,
        source=plugin.spec.name,
        varstore=registry.varstore,
        metadata={
            "pipeline_id": pipeline_id,
            "command_run_id": command_run_id,
            "parent_command_run_id": parent_command_run_id,
            "input_high_watermark": 0,
            "background": background,
            "from_run": from_run,
            "from_pipeline": from_pipeline,
            "from_topic": from_topic,
        },
    )
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
