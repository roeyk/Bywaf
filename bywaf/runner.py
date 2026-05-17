"""Command parser, foreground execution, and background process runner."""

from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .db import EventStore, Subscription
from .events import Event
from .plugin import CommandContext, implied_capabilities
from .registry import PluginRegistry
from .varstore import VarStore
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
    replay_after_id: int = 0
    note: str | None = None


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
    text, note = peel_note_selector(text)
    tokens = shlex.split(text)
    background = False
    if tokens:
        tokens, background = peel_background_marker(tokens)
    if not tokens:
        raise ValueError("empty command")
    name, *args = tokens
    args, selectors = peel_context_selectors(args)
    return CommandInvocation(
        name=name,
        args=args,
        background=background,
        from_run=selectors["from_run"],
        from_pipeline=selectors["from_pipeline"],
        from_topic=selectors["from_topic"],
        note=note,
    )


def parse_pipeline(command_line: str) -> Pipeline:
    """Parse a full pipeline and detect foreground/background execution."""
    parts, background = split_pipeline(command_line)
    if not parts:
        raise ValueError("empty pipeline")
    commands = list(parse_invocation(part) for part in parts)
    if background and commands:
        last = commands[-1]
        commands[-1] = CommandInvocation(
            last.name,
            last.args,
            background=True,
            from_run=last.from_run,
            from_pipeline=last.from_pipeline,
            from_topic=last.from_topic,
            replay_after_id=last.replay_after_id,
            note=last.note,
        )
    return Pipeline(tuple(commands), any(command.background for command in commands))


@dataclass(frozen=True, slots=True)
class StageRun:
    """Execution identity assigned to one pipeline stage."""

    invocation: CommandInvocation
    command_run_id: str
    parent_command_run_id: str | None


@dataclass(frozen=True, slots=True)
class StageResult:
    """Events produced by one executed pipeline stage."""

    events: list[Event]


@dataclass(frozen=True, slots=True)
class AtFileExpansion:
    """One framework-level at-file expansion applied to commandlet args."""

    token: str
    mode: Literal["text", "lines", "raw"]
    path: Path
    produced: int


@dataclass(slots=True)
class JobLifecycle:
    """Small helper for publishing consistent job lifecycle events."""

    db: EventStore
    job_id: int
    command_line: str
    request_event: Event | None = None

    @classmethod
    def create(cls, db: EventStore, command_line: str, pid: int | None, status: str = "queued") -> "JobLifecycle":
        """Record a new job and its requested event."""
        job_id = db.record_job(command_line.strip(), pid, status)
        lifecycle = cls(db, job_id, command_line.strip())
        lifecycle.request_event = lifecycle.requested()
        return lifecycle

    def requested(self) -> Event:
        """Publish that the framework accepted a job request."""
        return self.db.publish("job.requested", {"job_id": self.job_id, "command": self.command_line}, "runner")

    def claim(self, pid: int | None) -> bool:
        """Try to claim the job for one process and audit the result."""
        if not self.db.claim_job(self.job_id, pid):
            self.db.publish("job.claim.denied", {"job_id": self.job_id, "pid": pid}, "runner")
            return False
        self.db.publish("job.claimed", {"job_id": self.job_id, "pid": pid}, "runner")
        return True

    def start(self, pid: int | None) -> None:
        """Mark the job running and publish the start event."""
        self.db.update_job_status(self.job_id, "running")
        self.db.publish("job.started", {"job_id": self.job_id, "pid": pid, "command": self.command_line}, "runner")

    def fail(self, error: str) -> None:
        """Mark the job failed and publish the failure event."""
        self.db.publish("job.failed", {"job_id": self.job_id, "error": error}, "runner")
        self.db.finish_job(self.job_id, "failed")

    def finish(self) -> None:
        """Mark the job finished and publish the completion event."""
        self.db.publish("job.finished", {"job_id": self.job_id, "command": self.command_line}, "runner")
        self.db.finish_job(self.job_id, "finished")


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
        pid = os.getpid()
        lifecycle = JobLifecycle.create(self.db, command_line, pid)
        if not lifecycle.claim(pid):
            raise RuntimeError(f"could not claim foreground job {lifecycle.job_id}")
        lifecycle.start(pid)
        previous_job_id = self.job_id
        self.job_id = lifecycle.job_id
        try:
            events = self.run_pipeline(commands)
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
    ) -> list[Event]:
        """Run all stages in-process and return produced events.

        Foreground pipelines pass events from one stage directly into the next,
        while every yielded payload is also persisted to SQLite with pipeline
        and command-run scope IDs.
        """
        pipeline_id = pipeline_id or new_run_id("pipeline")
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
            plugin = self.registry.get(stage.invocation.name)
            ensure_run_var_snapshot(
                self.db,
                self.registry.varstore,
                job_id=self.job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                commandlet=plugin.spec.name,
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
                    stage.invocation.from_run,
                    stage.invocation.from_pipeline,
                    stage.invocation.from_topic,
                    stage.invocation.replay_after_id,
                    stage.invocation.note,
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
        pipeline = parse_pipeline(foreground)
        pipeline_id = new_run_id("pipeline")
        stages = prepare_stage_runs(pipeline.commands)
        lifecycle = JobLifecycle.create(self.db, foreground, None)
        for stage in stages:
            plugin = self.registry.get(stage.invocation.name)
            ensure_run_var_snapshot(
                self.db,
                self.registry.varstore,
                job_id=lifecycle.job_id,
                pipeline_id=pipeline_id,
                command_run_id=stage.command_run_id,
                commandlet=plugin.spec.name,
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
        from_cursor: str = "beginning",
    ) -> Event:
        """Attach one background commandlet to an existing pipeline."""
        if not pipeline_exists(self.db, pipeline_id):
            raise ValueError(f"unknown pipeline: {pipeline_id}")
        after_id = attach_cursor_event_id(self.db, from_cursor)
        parsed = parse_pipeline(command_line)
        if len(parsed.commands) != 1:
            raise ValueError("pipeline attach accepts exactly one commandlet")
        original = parsed.commands[0]
        invocation = CommandInvocation(
            original.name,
            original.args,
            background=True,
            from_run=upstream_run_id,
            from_pipeline=pipeline_id,
            from_topic=original.from_topic,
            replay_after_id=after_id,
            note=original.note,
        )
        stage = StageRun(invocation, new_run_id(invocation.name), upstream_run_id)
        lifecycle = JobLifecycle.create(
            self.db,
            f"pipeline attach {pipeline_id} {command_line} run={upstream_run_id or ''} from={from_cursor}".strip(),
            None,
        )
        plugin = self.registry.get(invocation.name)
        ensure_run_var_snapshot(
            self.db,
            self.registry.varstore,
            job_id=lifecycle.job_id,
            pipeline_id=pipeline_id,
            command_run_id=stage.command_run_id,
            commandlet=plugin.spec.name,
        )
        self.db.publish(
            "pipeline.attached",
            {
                "job_id": lifecycle.job_id,
                "pipeline_id": pipeline_id,
                "command": command_line,
                "command_run_id": stage.command_run_id,
                "parent_command_run_id": upstream_run_id,
                "from": from_cursor,
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
        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        pipeline = parse_pipeline(command_line)
        if pipeline.background:
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
        runner = Runner(db, PluginRegistry.discover(), job_id=job_id)
        runner.run_pipeline((stage.invocation,), pipeline_id=pipeline_id, stages=(stage,))
    except Exception as exc:
        lifecycle.fail(str(exc))
    else:
        lifecycle.finish()


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


def peel_note_selector(text: str) -> tuple[str, str | None]:
    """Remove a framework-owned `note=` selector from raw stage text.

    The selector is parsed before `shlex.split` so a final unquoted note can
    consume the rest of the command stage:

    `hostscanner targets note=client approved`
    """
    index = find_unquoted_note_selector(text)
    if index is None:
        return text, None
    note = normalize_note_text(text[index + len("note="):])
    if not note:
        raise ValueError("note= requires a value")
    return text[:index].rstrip(), note


def find_unquoted_note_selector(text: str) -> int | None:
    """Return the index of a token-boundary `note=` outside shell quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if text.startswith("note=", index) and (index == 0 or text[index - 1].isspace()):
            return index
    return None


def normalize_note_text(raw_note: str) -> str:
    """Return note text with shell quotes removed when possible."""
    stripped = raw_note.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    return " ".join(tokens)


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
        after_id=invocation.replay_after_id,
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
    return len(commands) == 1 and commands[0].name in {"db", "job", "pipeline"}


def effective_run_vars(varstore: VarStore, commandlet: str) -> dict[str, str]:
    """Return the session variables visible to one commandlet at launch time."""
    prefix = f"{commandlet}."
    return {
        key: value
        for key, value in varstore.items()
        if key.startswith(prefix) or key.startswith("global.")
    }


def ensure_run_var_snapshot(
    db: EventStore,
    varstore: VarStore,
    *,
    job_id: int | None,
    pipeline_id: str,
    command_run_id: str,
    commandlet: str,
) -> dict[str, str]:
    """Load or create the immutable variable snapshot for one command run."""
    existing = db.command_run_vars(command_run_id)
    if existing:
        return existing
    values = effective_run_vars(varstore, commandlet)
    db.record_command_run_vars(
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        commandlet=commandlet,
        values=values,
    )
    return values


def build_context(
    db: EventStore,
    registry: PluginRegistry,
    stage: StageRun,
    *,
    pipeline_id: str,
    job_id: int | None,
    input_high_watermark: int,
    replace_db,
    runner=None,
) -> CommandContext:
    """Build the runtime context for one commandlet stage."""
    invocation = stage.invocation
    plugin = registry.get(invocation.name)
    run_vars = ensure_run_var_snapshot(
        db,
        registry.varstore,
        job_id=job_id,
        pipeline_id=pipeline_id,
        command_run_id=stage.command_run_id,
        commandlet=plugin.spec.name,
    )
    return CommandContext(
        db,
        source=plugin.spec.name,
        _varstore=registry.varstore,
        metadata={
            "pipeline_id": pipeline_id,
            "command_run_id": stage.command_run_id,
            "parent_command_run_id": stage.parent_command_run_id,
            "input_high_watermark": input_high_watermark,
            "background": invocation.background,
            "from_run": invocation.from_run,
            "from_pipeline": invocation.from_pipeline,
            "from_topic": invocation.from_topic,
            "note": invocation.note,
            "replace_db": replace_db,
            "runner": runner,
            "job_id": job_id,
            "run_vars": run_vars,
            "capabilities": implied_capabilities(plugin.spec),
        },
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
    publish_note_if_present(db, context, invocation.note)
    expanded_args = expand_at_file_args(context, invocation.args)
    for input_topic in sorted({event.topic for event in selected_input_events}):
        context.audit_capability(f"db.read:{input_topic}")
    topic = plugin.spec.emits[0] if plugin.spec.emits else plugin.spec.name
    events = []
    for payload in plugin.run(context, expanded_args, selected_input_events):
        context.audit_capability(f"db.write:{topic}")
        events.append(db.publish(
            topic,
            payload,
            plugin.spec.name,
            pipeline_id=pipeline_id,
            command_run_id=stage.command_run_id,
            parent_command_run_id=stage.parent_command_run_id,
        ))
    return StageResult(events)


def expand_at_file_args(context: CommandContext, args: list[str]) -> list[str]:
    """Expand framework-level at-file arguments before plugin parsing."""
    expanded: list[str] = []
    for arg in args:
        values, expansion = expand_at_file_arg(arg)
        expanded.extend(values)
        if expansion is not None:
            context.audit_capability("filesystem.read")
            publish_at_file_expansion(context, expansion)
    return expanded


def expand_at_file_arg(arg: str) -> tuple[list[str], AtFileExpansion | None]:
    """Expand one `@` argument or return it unchanged."""
    if not arg.startswith("@"):
        return [arg], None
    if arg.startswith("@@"):
        return [arg[1:]], None
    mode, raw_path = parse_at_file_token(arg)
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise ValueError(f"at-file path does not exist: {path}")
    if path.is_dir():
        raise ValueError(f"at-file path is a directory: {path}")
    text = path.read_text(errors="replace")
    match mode:
        case "lines":
            values = [line.strip() for line in text.splitlines() if line.strip()]
        case "text" | "raw":
            values = [text]
    return values, AtFileExpansion(arg, mode, path, len(values))


def parse_at_file_token(arg: str) -> tuple[Literal["text", "lines", "raw"], str]:
    """Return expansion mode and path for one at-file token."""
    if arg.startswith("@lines:"):
        return "lines", arg.removeprefix("@lines:")
    if arg.startswith("@raw:"):
        return "raw", arg.removeprefix("@raw:")
    return "text", arg.removeprefix("@")


def publish_at_file_expansion(context: CommandContext, expansion: AtFileExpansion) -> Event | None:
    """Record one framework-owned at-file expansion."""
    if context._db is None:
        return None
    return context._db.publish(
        "framework.argument.expanded",
        {
            "operator": "@",
            "token": expansion.token,
            "mode": expansion.mode,
            "path": str(expansion.path),
            "produced": expansion.produced,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "commandlet": context.source,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_note_if_present(db: EventStore, context: CommandContext, note: str | None) -> Event | None:
    """Persist a framework-owned note attached to this command run."""
    if note is None:
        return None
    return db.publish(
        "note.attached",
        {
            "note": note,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "parent_command_run_id": context.parent_command_run_id,
            "commandlet": context.source,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


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
    replay_after_id: int,
    note: str | None,
) -> None:
    """Child-process entry point for one background pipeline stage."""
    db = EventStore(Path(db_path), passphrase=db_passphrase)
    registry = PluginRegistry.discover()
    stage = StageRun(
        CommandInvocation(
            name,
            args,
            background=background,
            from_run=from_run,
            from_pipeline=from_pipeline,
            from_topic=from_topic,
            replay_after_id=replay_after_id,
            note=note,
        ),
        command_run_id,
        parent_command_run_id,
    )
    execute_stage(db, registry, stage, pipeline_id=pipeline_id, job_id=job_id, input_events=[])


def pipeline_exists(db: EventStore, pipeline_id: str) -> bool:
    """Return whether the DB knows this pipeline id."""
    return any(row["pipeline_id"] == pipeline_id for row in db.pipelines())


def attach_cursor_event_id(db: EventStore, cursor: str) -> int:
    """Convert an attach `from=` cursor into an event high-water mark."""
    match cursor:
        case "beginning":
            return 0
        case "now":
            return db.latest_event_id()
        case _:
            raise ValueError("from= must be beginning or now")
