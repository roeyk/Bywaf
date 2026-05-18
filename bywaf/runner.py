"""Command parser, foreground execution, and background process runner."""

from __future__ import annotations

import argparse
import getpass
import multiprocessing as mp
import os
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .db import EventStore, Subscription
from .events import Event
from .plugin import CommandContext, PlanRepair, PlanReport, implied_capabilities
from .registry import PluginRegistry
from .varstore import VarStore


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
    display_name: str | None = None
    variable_expansions: tuple[str, ...] = ()
    plan_only: bool = False
    approved: bool = False


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A sequence of commandlets connected by pipe syntax."""

    commands: tuple[CommandInvocation, ...]
    background: bool = False
    display_name: str | None = None


def parse_invocation(text: str, varstore: VarStore | None = None) -> CommandInvocation:
    """Parse one commandlet expression.

    This function strips Bywaf framework selectors such as `--from-run` before
    plugin argparse sees the remaining plugin-owned arguments.
    """
    text, display_name = peel_final_text_selector(text, "name")
    text, note = peel_final_text_selector(text, "note")
    commandlet = provisional_command_name(text)
    variable_expansions: tuple[str, ...] = ()
    if varstore is not None and commandlet is not None:
        text, variable_expansions = expand_variables_in_text(text, varstore, commandlet)
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
        display_name=display_name,
        variable_expansions=variable_expansions,
        plan_only=selectors["plan_only"] == "true",
        approved=selectors["approved"] == "true",
    )


def parse_pipeline(command_line: str, varstore: VarStore | None = None) -> Pipeline:
    """Parse a full pipeline and detect foreground/background execution."""
    command_line, display_name = peel_pipeline_name_prefix(command_line)
    parts, background = split_pipeline_raw(command_line)
    if not parts:
        raise ValueError("empty pipeline")
    commands = list(parse_invocation(part, varstore=varstore) for part in parts)
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
            display_name=last.display_name,
            variable_expansions=last.variable_expansions,
            plan_only=last.plan_only,
            approved=last.approved,
        )
    return Pipeline(tuple(commands), any(command.background for command in commands), display_name)


def split_pipeline_raw(command_line: str) -> tuple[list[str], bool]:
    """Split a pipeline without changing quote context inside each stage."""
    command_line, background = peel_pipeline_background(command_line)
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
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
        if char == "|":
            part = command_line[start:index].strip()
            if part:
                parts.append(part)
            start = index + 1
    final = command_line[start:].strip()
    if final:
        parts.append(final)
    return parts, background


def peel_pipeline_background(command_line: str) -> tuple[str, bool]:
    """Remove a trailing standalone `&` from a full pipeline expression."""
    stripped = command_line.rstrip()
    if not stripped.endswith("&"):
        return command_line, False
    amp_index = len(stripped) - 1
    if amp_index == 0 or not stripped[amp_index - 1].isspace():
        return command_line, False
    if is_quoted_position(stripped, amp_index):
        return command_line, False
    return stripped[:amp_index].rstrip(), True


def is_quoted_position(text: str, position: int) -> bool:
    """Return whether one character index is inside shell-style quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if index == position:
            return quote is not None
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
    return False


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
    job_serial: str | None = None

    @classmethod
    def create(cls, db: EventStore, command_line: str, pid: int | None, status: str = "queued") -> "JobLifecycle":
        """Record a new job and its requested event."""
        job_id = db.record_job(command_line.strip(), pid, status)
        lifecycle = cls(db, job_id, command_line.strip())
        lifecycle.job_serial = db.job_serial(job_id)
        lifecycle.request_event = lifecycle.requested()
        return lifecycle

    def requested(self) -> Event:
        """Publish that the framework accepted a job request."""
        return self.db.publish("job.requested", self.payload({"command": self.command_line}), "runner")

    def claim(self, pid: int | None) -> bool:
        """Try to claim the job for one process and audit the result."""
        if not self.db.claim_job(self.job_id, pid):
            self.db.publish("job.claim.denied", self.payload({"pid": pid}), "runner")
            return False
        self.db.publish("job.claimed", self.payload({"pid": pid}), "runner")
        return True

    def start(self, pid: int | None) -> None:
        """Mark the job running and publish the start event."""
        self.db.update_job_status(self.job_id, "running")
        self.db.publish("job.started", self.payload({"pid": pid, "command": self.command_line}), "runner")

    def fail(self, error: str) -> None:
        """Mark the job failed and publish the failure event."""
        self.db.publish("job.failed", self.payload({"error": error}), "runner")
        self.db.finish_job(self.job_id, "failed")

    def finish(self) -> None:
        """Mark the job finished and publish the completion event."""
        self.db.publish("job.finished", self.payload({"command": self.command_line}), "runner")
        self.db.finish_job(self.job_id, "finished")

    def payload(self, values: dict[str, object]) -> dict[str, object]:
        """Return job lifecycle payload values with local and serial IDs."""
        if self.job_serial is None:
            self.job_serial = self.db.job_serial(self.job_id)
        return {
            "job_id": self.job_id,
            "job_serial": self.job_serial,
            "serial": self.job_serial,
            **values,
        }


class Runner:
    """Execute parsed commandlet pipelines against an EventStore."""

    def __init__(self, db: EventStore, registry: PluginRegistry, *, job_id: int | None = None):
        self.db = db
        self.registry = registry
        self.job_id = job_id

    def execute(self, command_line: str) -> list[Event]:
        """Run a command line immediately or start it as a background job."""
        pipeline = parse_pipeline(command_line, varstore=self.registry.varstore)
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
        and command-run scope IDs.
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
        pipeline = pipeline or parse_pipeline(foreground, varstore=self.registry.varstore)
        pipeline_id = new_run_id("pipeline")
        if pipeline.display_name:
            publish_runtime_name(self.db, "pipeline", pipeline_id, pipeline.display_name, pipeline_id=pipeline_id)
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
        since_cursor: str = "beginning",
    ) -> Event:
        """Attach one background commandlet to an existing pipeline."""
        if not pipeline_exists(self.db, pipeline_id):
            raise ValueError(f"unknown pipeline: {pipeline_id}")
        after_id = attach_cursor_event_id(self.db, since_cursor)
        parsed = parse_pipeline(command_line, varstore=self.registry.varstore)
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
            display_name=original.display_name,
            variable_expansions=original.variable_expansions,
            plan_only=original.plan_only,
            approved=original.approved,
        )
        stage = StageRun(invocation, new_run_id(invocation.name), upstream_run_id)
        lifecycle = JobLifecycle.create(
            self.db,
            f"pipeline attach {pipeline_id} {command_line} run={upstream_run_id or ''} since={since_cursor}".strip(),
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


def peel_final_text_selector(text: str, key: str) -> tuple[str, str | None]:
    """Remove a framework-owned final text selector from raw stage text.

    The selector is parsed before `shlex.split` so a final unquoted note can
    consume the rest of the command stage:

    `hostscanner targets note=client approved`
    """
    index = find_unquoted_text_selector(text, key)
    if index is None:
        return text, None
    value = normalize_final_text(text[index + len(key) + 1:])
    if not value:
        raise ValueError(f"{key}= requires a value")
    return text[:index].rstrip(), value


def find_unquoted_text_selector(text: str, key: str) -> int | None:
    """Return the index of a token-boundary text selector outside shell quotes."""
    quote: str | None = None
    escaped = False
    needle = f"{key}="
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
        if text.startswith(needle, index) and (index == 0 or text[index - 1].isspace()):
            return index
    return None


def normalize_final_text(raw_value: str) -> str:
    """Return selector text with shell quotes removed when possible."""
    stripped = raw_value.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    return " ".join(tokens)


def provisional_command_name(text: str) -> str | None:
    """Return the first command token before variable expansion."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    return tokens[0] if tokens else None


def expand_variables_in_text(text: str, varstore: VarStore, commandlet: str) -> tuple[str, tuple[str, ...]]:
    """Expand `$variables` outside single quotes before shell tokenization."""
    output: list[str] = []
    expanded: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            output.append(char)
            escaped = True
            index += 1
            continue
        if quote == "'":
            output.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == '"':
            output.append(char)
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char == "'":
            output.append(char)
            quote = "'"
            index += 1
            continue
        if char != "$":
            output.append(char)
            index += 1
            continue
        parsed = parse_variable_reference(text, index)
        if parsed is None:
            output.append(char)
            index += 1
            continue
        name, end = parsed
        value, resolved_name = resolve_variable_reference(varstore, commandlet, name)
        replacement = escape_double_quoted_value(value) if quote == '"' else value
        output.append(replacement)
        expanded.append(resolved_name)
        index = end
    return "".join(output), tuple(dict.fromkeys(expanded))


def parse_variable_reference(text: str, dollar_index: int) -> tuple[str, int] | None:
    """Return a variable name and end index for `$name` or `${name}`."""
    start = dollar_index + 1
    if start >= len(text):
        return None
    if text[start] == "{":
        end = text.find("}", start + 1)
        if end == -1:
            raise ValueError("unterminated variable reference")
        name = text[start + 1:end]
        if not name:
            raise ValueError("empty variable reference")
        return name, end + 1
    if not (text[start].isalpha() or text[start] == "_"):
        return None
    end = start + 1
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return text[start:end], end


def resolve_variable_reference(varstore: VarStore, commandlet: str, name: str) -> tuple[str, str]:
    """Resolve a `$variable` against exact, commandlet, then global scopes."""
    candidates = [name]
    if "." not in name:
        candidates.extend((f"{commandlet}.{name}", f"global.{name}"))
    for candidate in candidates:
        value = varstore.get(candidate)
        if value is not None:
            return value, candidate
    raise ValueError(f"unknown variable: ${name}")


def escape_double_quoted_value(value: str) -> str:
    """Escape replacement text that is inserted inside double quotes."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def peel_pipeline_name_prefix(command_line: str) -> tuple[str, str | None]:
    """Remove a leading `pipeline name: command` prefix when present."""
    index = find_pipeline_name_colon(command_line)
    if index is None:
        return command_line, None
    display_name = normalize_final_text(command_line[:index])
    command = command_line[index + 1:].strip()
    if not display_name or not command:
        return command_line, None
    return command, display_name


def find_pipeline_name_colon(command_line: str) -> int | None:
    """Find a top-level naming colon followed by whitespace before any pipe."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
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
        if char == "|":
            return None
        if char == ":" and index + 1 < len(command_line) and command_line[index + 1].isspace():
            return index
    return None


def peel_context_selectors(args: list[str]) -> tuple[list[str], dict[str, str | None]]:
    """Remove framework-owned selector flags from plugin arguments."""
    selectors: dict[str, str | None] = {
        "from_run": None,
        "from_pipeline": None,
        "from_topic": None,
        "plan_only": "false",
        "approved": "false",
    }
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
            case "--test":
                selectors["plan_only"] = "true"
                index += 1
            case "--yes":
                selectors["approved"] = "true"
                index += 1
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
        command_run_id=db.resolve_run_serial(invocation.from_run) if invocation.from_run else None,
        pipeline_id=db.resolve_pipeline_serial(invocation.from_pipeline) if invocation.from_pipeline else None,
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
    """Publish command-run lifecycle events used by finite listeners."""
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


def handle_plan_if_needed(
    context: CommandContext,
    plugin,
    args: list[str],
    input_events: list[Event],
    invocation: CommandInvocation,
) -> list[str] | None:
    """Run a commandlet plan hook, audit it, and enforce approval if needed."""
    planner = getattr(plugin, "plan", None)
    if planner is None:
        if invocation.plan_only:
            context.output(f"{plugin.spec.name}: no plan available")
            return None
        return args
    report = planner(context, args, input_events)
    if not isinstance(report, PlanReport):
        raise ValueError(f"{plugin.spec.name} plan() must return PlanReport")
    must_approve = report.requires_confirmation or bool(report.warnings)
    if not invocation.plan_only and not must_approve:
        return args
    request = publish_plan_requested(context, report)
    publish_policy_evaluated(context, request, report)
    context.output(format_plan_report(report))
    repaired_args = maybe_apply_plan_repair(context, request, report, invocation)
    if invocation.plan_only:
        return None
    if not must_approve:
        return repaired_args or args
    if invocation.approved:
        publish_plan_decision(context, request, True, "cli-yes", "--yes")
        return repaired_args or args
    if context.background:
        publish_plan_decision(context, request, False, "background", "missing --yes")
        raise ValueError(f"{plugin.spec.name} plan requires --yes for background execution")
    answer = input("Approve this plan? type YES: ")
    approved = answer == "YES"
    publish_plan_decision(context, request, approved, "interactive", answer)
    if not approved:
        raise ValueError("plan denied")
    return repaired_args or args


def maybe_apply_plan_repair(
    context: CommandContext,
    request: Event,
    report: PlanReport,
    invocation: CommandInvocation,
) -> list[str] | None:
    """Apply the first suggested repair when the operator or --yes accepts it."""
    if not report.repairs:
        return None
    repair = report.repairs[0]
    if invocation.approved:
        publish_plan_repair(context, request, repair, approved=True, method="cli-yes", answer="--yes")
        return list(repair.patched_args)
    if invocation.plan_only or context.background:
        return None
    answer = input(f"Apply suggested repair '{repair.name}'? type YES: ")
    approved = answer == "YES"
    publish_plan_repair(context, request, repair, approved=approved, method="interactive", answer=answer)
    return list(repair.patched_args) if approved else None


def publish_plan_requested(context: CommandContext, report: PlanReport) -> Event:
    """Persist the plan report shown to the operator."""
    if context._db is None:
        raise ValueError("plan auditing requires an active database")
    return context._db.publish(
        "plan.requested",
        {
            "commandlet": context.source,
            "action": report.action,
            "summary": report.summary,
            "items": [
                {"kind": item.kind, "value": item.value, "details": item.details}
                for item in report.items
            ],
            "warnings": list(report.warnings),
            "repairs": [
                {
                    "name": repair.name,
                    "description": repair.description,
                    "before": repair.before,
                    "after": repair.after,
                }
                for repair in report.repairs
            ],
            "requires_confirmation": report.requires_confirmation,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_policy_evaluated(context: CommandContext, request: Event, report: PlanReport) -> Event:
    """Persist the framework policy decision for a plan."""
    if context._db is None:
        raise ValueError("policy auditing requires an active database")
    decision = "warn" if report.warnings else "allow"
    return context._db.publish(
        "policy.evaluated",
        {
            "request_event_id": request.id,
            "decision": decision,
            "warnings": list(report.warnings),
            "repairs": [repair.name for repair in report.repairs],
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_plan_decision(context: CommandContext, request: Event, approved: bool, method: str, answer: str) -> Event:
    """Persist the operator's approval or denial of a plan."""
    if context._db is None:
        raise ValueError("plan approval auditing requires an active database")
    return context._db.publish(
        "plan.approved" if approved else "plan.denied",
        {
            "request_event_id": request.id,
            "approved": approved,
            "approval_method": method,
            "answer": answer,
            "approved_by": getpass.getuser(),
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_plan_repair(
    context: CommandContext,
    request: Event,
    repair: PlanRepair,
    *,
    approved: bool,
    method: str,
    answer: str,
) -> Event:
    """Persist the operator's decision about a suggested plan repair."""
    if context._db is None:
        raise ValueError("plan repair auditing requires an active database")
    return context._db.publish(
        "plan.repair.applied" if approved else "plan.repair.denied",
        {
            "request_event_id": request.id,
            "repair": repair.name,
            "description": repair.description,
            "approved": approved,
            "approval_method": method,
            "answer": answer,
            "approved_by": getpass.getuser(),
            "before": repair.before,
            "after": repair.after,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def format_plan_report(report: PlanReport) -> str:
    """Return a compact human-readable plan report."""
    lines = [f"Plan: {report.action}", report.summary]
    if report.items:
        lines.append("Items:")
        lines.extend(f"  {item.kind}: {item.value}" for item in report.items)
    if report.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in report.warnings)
    if report.repairs:
        lines.append("Suggested repairs:")
        lines.extend(f"  {repair.name}: {repair.description}" for repair in report.repairs)
    return "\n".join(lines)


def expand_at_file_args(context: CommandContext, args: list[str]) -> list[str]:
    """Expand framework-level at-file arguments before plugin parsing."""
    expanded: list[str] = []
    for arg in args:
        values, expansion = expand_at_file_arg(arg)
        expanded.extend(values)
        if expansion is not None:
            context.audit_capability("filesystem.read")
            artifact_id = attach_at_file_artifact(context, expansion)
            publish_at_file_expansion(context, expansion, artifact_id=artifact_id)
    return expanded


def expand_at_file_arg(arg: str) -> tuple[list[str], AtFileExpansion | None]:
    """Expand one `@` argument or return it unchanged."""
    if "=@" in arg and not arg.startswith("@"):
        key, value = arg.split("=", 1)
        values, expansion = expand_at_file_arg(value)
        return [f"{key}={','.join(values)}"], expansion
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


def attach_at_file_artifact(context: CommandContext, expansion: AtFileExpansion) -> str | None:
    """Attach an expanded input file as provenance when artifact storage works."""
    try:
        artifact = context.artifacts.attach_file(
            expansion.path,
            name=expansion.path.name,
            note=f"framework argument expansion {expansion.mode} from {expansion.token}",
        )
    except (RuntimeError, ValueError):
        return None
    return artifact.artifact_id


def publish_at_file_expansion(
    context: CommandContext,
    expansion: AtFileExpansion,
    *,
    artifact_id: str | None = None,
) -> Event | None:
    """Record one framework-owned at-file expansion."""
    if context._db is None:
        return None
    payload = {
        "operator": "@",
        "token": expansion.token,
        "mode": expansion.mode,
        "path": str(expansion.path),
        "produced": expansion.produced,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "commandlet": context.source,
    }
    if artifact_id is not None:
        payload["artifact_id"] = artifact_id
    return context._db.publish(
        "framework.argument.expanded",
        payload,
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_variable_expansion(context: CommandContext, variable_names: tuple[str, ...]) -> Event | None:
    """Record framework-owned `$variable` expansion for this command run."""
    if not variable_names or context._db is None:
        return None
    context.audit_capability("variable.read")
    return context._db.publish(
        "framework.variable.expanded",
        {
            "operator": "$",
            "variables": list(variable_names),
            "count": len(variable_names),
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


def publish_runtime_name(
    db: EventStore,
    target_type: str,
    target_id: str | int,
    display_name: str,
    *,
    job_id: int | None = None,
    pipeline_id: str | None = None,
    command_run_id: str | None = None,
    parent_command_run_id: str | None = None,
) -> Event:
    """Persist a user-assigned runtime name."""
    return db.publish(
        "runtime.name.assigned",
        {
            "target_type": target_type,
            "target_id": str(target_id),
            "name": display_name,
            "job_id": job_id,
            "pipeline_id": pipeline_id,
            "command_run_id": command_run_id,
            "parent_command_run_id": parent_command_run_id,
        },
        "framework",
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        parent_command_run_id=parent_command_run_id,
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
            from_run=from_run,
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


def pipeline_exists(db: EventStore, pipeline_id: str) -> bool:
    """Return whether the DB knows this pipeline id."""
    return any(row["pipeline_id"] == pipeline_id for row in db.pipelines())


def attach_cursor_event_id(db: EventStore, cursor: str) -> int:
    """Convert an attach `since=` cursor into an event high-water mark."""
    match cursor:
        case "beginning":
            return 0
        case "now":
            return db.latest_event_id()
        case _:
            raise ValueError("since= must be beginning or now")
