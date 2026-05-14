"""Plugin protocol and shared dataclasses."""

from __future__ import annotations

import argparse
import selectors
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from .db import EventStore, Subscription
from .events import Event
from .varstore import ScopedVarStore, VarStore


@dataclass(frozen=True, slots=True)
class CompletionSpec:
    """Declarative completion behavior for an option or argument."""

    kind: str = "none"
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    """Metadata for one positional argument.

    Runtime validation still belongs to the commandlet's parser; this metadata
    is for help, introspection, and shell completion.
    """

    name: str
    description: str = ""
    required: bool = True
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """Metadata for one long option exposed by a commandlet."""

    name: str
    description: str
    default: str | None = None
    choices: tuple[str, ...] = ()
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Public commandlet contract consumed by help and completion."""

    name: str
    description: str
    usage: str = ""
    examples: tuple[str, ...] = ()
    options: tuple[OptionSpec, ...] = ()
    arguments: tuple[ArgumentSpec, ...] = ()
    consumes: tuple[str, ...] = ()
    emits: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()


def commandlet(
    *,
    name: str,
    description: str,
    usage: str = "",
    examples: Sequence[str] = (),
    consumes: Sequence[str] = (),
    emits: Sequence[str] = (),
    capabilities: Sequence[str] = (),
):
    """Decorate a commandlet class with a `CommandSpec`.

    Use this with `@argument` and `@option` to keep plugin metadata readable
    without hand-writing a full `CommandSpec` block.
    """
    def decorate(cls):
        cls.spec = CommandSpec(
            name=name,
            description=description,
            usage=usage,
            examples=tuple(examples),
            options=tuple(getattr(cls, "_bywaf_options", ())),
            arguments=tuple(getattr(cls, "_bywaf_arguments", ())),
            consumes=tuple(consumes),
            emits=tuple(emits),
            capabilities=tuple(capabilities),
        )
        return cls

    return decorate


def option(
    name: str,
    description: str,
    default: str | None = None,
    choices: Sequence[str] = (),
    completion: CompletionSpec | str | None = None,
):
    """Decorate a commandlet class with one option metadata entry."""
    def decorate(cls):
        options = list(cast(tuple[OptionSpec, ...], getattr(cls, "_bywaf_options", ())))
        options.insert(
            0,
            OptionSpec(
                name,
                description,
                default,
                tuple(choices),
                normalize_completion(completion),
            )
        )
        cls._bywaf_options = tuple(options)
        return cls

    return decorate


def argument(
    name: str,
    description: str = "",
    *,
    required: bool = True,
    completion: CompletionSpec | str | None = None,
):
    """Decorate a commandlet class with one positional argument metadata entry."""
    def decorate(cls):
        arguments = list(cast(tuple[ArgumentSpec, ...], getattr(cls, "_bywaf_arguments", ())))
        arguments.insert(
            0,
            ArgumentSpec(
                name,
                description,
                required=required,
                completion=normalize_completion(completion),
            )
        )
        cls._bywaf_arguments = tuple(arguments)
        return cls

    return decorate


def normalize_completion(completion: CompletionSpec | str | None) -> CompletionSpec:
    """Convert decorator completion shorthand into a `CompletionSpec`."""
    if completion is None:
        return CompletionSpec()
    if isinstance(completion, CompletionSpec):
        return completion
    return CompletionSpec(completion)


@dataclass(init=False, slots=True)
class CommandContext:
    """Runtime context passed into commandlets."""

    _db: EventStore | None
    source: str
    _varstore: VarStore
    metadata: dict[str, Any]

    def __init__(
        self,
        db: EventStore | None,
        source: str,
        _varstore: VarStore | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Create a command context while preserving the public `db=` keyword."""
        self._db = db
        self.source = source
        self._varstore = _varstore or VarStore()
        self.metadata = metadata or {}

    @property
    def db(self) -> EventStore | None:
        """Return raw database access for privileged/internal commandlets.

        Normal plugins should use `context.events`. Raw DB access is audited as
        `db.raw` so future enforcement can distinguish privileged commandlets
        from normal event-bus users.
        """
        if self._db is not None:
            self.audit_capability("db.raw")
        return self._db

    @db.setter
    def db(self, value: EventStore | None) -> None:
        """Replace the raw database handle for internal DB-management code."""
        self._db = value

    @property
    def vars(self) -> ScopedVarStore:
        """Return this commandlet's scoped variable view."""
        return ScopedVarStore(
            self._varstore,
            self.source,
            self.metadata.get("run_vars", {}),
        )

    @property
    def events(self) -> "ContextEvents":
        """Return the mediated event-bus API for plugin code."""
        return ContextEvents(self)

    @property
    def process(self) -> "ContextProcess":
        """Return the mediated process-execution API for plugin code."""
        return ContextProcess(self)

    @property
    def pipeline_id(self) -> str | None:
        """Return the current pipeline ID, if this commandlet has one."""
        value = self.metadata.get("pipeline_id")
        return str(value) if value is not None else None

    @property
    def command_run_id(self) -> str | None:
        """Return the current command-run ID, if this commandlet has one."""
        value = self.metadata.get("command_run_id")
        return str(value) if value is not None else None

    @property
    def parent_command_run_id(self) -> str | None:
        """Return the upstream command-run ID for a pipeline stage, if present."""
        value = self.metadata.get("parent_command_run_id")
        return str(value) if value is not None else None

    @property
    def job_id(self) -> int | str | None:
        """Return the active job ID, if this commandlet is job-scoped."""
        return self.metadata.get("job_id")

    @property
    def background(self) -> bool:
        """Return whether this commandlet is running as a background stage."""
        return bool(self.metadata.get("background"))

    @property
    def input_high_watermark(self) -> int:
        """Return the highest upstream event ID already consumed."""
        value = self.metadata.get("input_high_watermark", 0)
        return int(value) if value is not None else 0

    def require_db(self, label: str | None = None) -> EventStore:
        """Return the active DB or raise a consistent user-facing error."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires an active database")
        self.audit_capability("db.raw")
        return self._db

    def require_foreground(self, label: str | None = None) -> None:
        """Raise if a foreground-only commandlet is running in the background."""
        if self.background:
            raise ValueError(f"{label or self.source} must run in the foreground")

    def cancelled(self) -> bool:
        """Return whether this job, pipeline, or command run was cancelled."""
        if self._db is None:
            return False
        return self._db.cancellation_requested(
            job_id=self.job_id,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
        )

    def raise_if_cancelled(self) -> None:
        """Raise a clear exception when a soft-cancellation request is pending."""
        if self.cancelled():
            raise RuntimeError("commandlet cancelled")

    def request(self, topic: str, payload: dict[str, Any]) -> Event | None:
        """Write a framework request event with this commandlet's run scope."""
        if self._db is None:
            return None
        event = self._db.publish(
            topic,
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        capability = framework_request_capability(topic)
        if capability is not None:
            self.audit_capability(capability, request_event_id=event.id)
        return event

    def audit_capability(self, capability: str, *, request_event_id: int | None = None) -> None:
        """Record audit-only capability usage for this commandlet run."""
        if self._db is None:
            return
        declared = capability_declared(capability, self.declared_capabilities)
        payload = {
            "commandlet": self.source,
            "capability": capability,
            "declared": declared,
            "request_event_id": request_event_id,
            "job_id": self.job_id,
        }
        self._db.publish(
            "plugin.capability.used",
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        if not declared:
            self._db.publish(
                "plugin.capability.missing",
                payload,
                self.source,
                pipeline_id=self.pipeline_id,
                command_run_id=self.command_run_id,
                parent_command_run_id=self.parent_command_run_id,
            )

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        """Return capabilities declared or implied for this commandlet."""
        value = self.metadata.get("capabilities", ())
        return tuple(str(capability) for capability in value)

    def output(self, text: object = "", *, end: str = "\n") -> None:
        """Request normal command output from the framework console."""
        payload = {
            "text": str(text),
            "end": end,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.output.requested", payload) is None:
            print(str(text), end=end, flush=True)

    def table(self, rows: Iterable[Mapping[str, object] | Sequence[object]], columns: Sequence[str] | None = None) -> None:
        """Render a small text table through the framework output path."""
        normalized = list(rows)
        if not normalized:
            return
        if columns is None:
            first = normalized[0]
            if isinstance(first, Mapping):
                columns = tuple(str(column) for column in first.keys())
            else:
                columns = tuple(str(index) for index in range(len(first)))
        lines = format_table(normalized, columns)
        if lines:
            self.output("\n".join(lines))

    def alert(self, message: str, *, level: str = "alert", silent: bool = False) -> None:
        """Request a framework-owned console alert.

        Commandlets should not write operator alerts directly to stdout. They
        request the alert through the event database so the interpreter can
        validate, display, suppress, or route it consistently.
        """
        payload = {
            "message": message,
            "level": level,
            "silent": silent,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.alert.requested", payload) is None and not silent:
            print(f"{self.source} <{command_run_id(self)}>: {message}", flush=True)

    def page_file(self, path: str | Path) -> None:
        """Request framework-owned file paging for terminal and GUI frontends."""
        file_path = Path(path).expanduser()
        payload = {
            "path": str(file_path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
        }
        if self.request("framework.file.page.requested", payload) is None:
            print(file_path.read_text(errors="replace"), end="", flush=True)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Normalized result from a framework-mediated process run."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    request_event_id: int | None = None

    @property
    def ok(self) -> bool:
        """Return whether the process exited successfully."""
        return self.returncode == 0

    def check_returncode(self) -> None:
        """Raise `CalledProcessError` when the process failed."""
        if self.returncode != 0:
            raise subprocess.CalledProcessError(
                self.returncode,
                list(self.argv),
                output=self.stdout,
                stderr=self.stderr,
            )


@dataclass(frozen=True, slots=True)
class ProcessChunk:
    """One streamed stdout/stderr chunk from a framework-mediated process."""

    argv: tuple[str, ...]
    stream: str
    text: str
    request_event_id: int | None = None


@dataclass(frozen=True, slots=True)
class ContextProcess:
    """Framework-mediated process API exposed to commandlets.

    Plugins should use this instead of importing `subprocess` directly. The API
    records the request, audits the `process.run` capability, executes an argv
    vector with `shell=False`, and records the result for later inspection.
    """

    context: CommandContext

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None = None,
        timeout: float | None = None,
        check: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> ProcessResult:
        """Run an external command through the framework audit path."""
        normalized = normalize_argv(argv)
        payload: dict[str, Any] = {
            "argv": list(normalized),
            "cwd": str(Path(cwd).expanduser()) if cwd is not None else None,
            "timeout": timeout,
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "handled": True,
        }
        request = self.context.request("framework.process.run.requested", payload)
        completed = run_process_argv(normalized, cwd=payload["cwd"], env=env, timeout=timeout)
        result = ProcessResult(
            argv=normalized,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            request_event_id=request.id if request is not None else None,
        )
        self.publish_result(result)
        if check:
            result.check_returncode()
        return result

    def stream(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None = None,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> Iterable[ProcessChunk]:
        """Stream stdout/stderr line chunks while recording process events."""
        normalized = normalize_argv(argv)
        payload: dict[str, Any] = {
            "argv": list(normalized),
            "cwd": str(Path(cwd).expanduser()) if cwd is not None else None,
            "timeout": timeout,
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "handled": True,
            "mode": "stream",
        }
        request = self.context.request("framework.process.stream.requested", payload)
        request_id = request.id if request is not None else None
        self.publish_started(normalized, request_id)
        process = popen_process_argv(normalized, cwd=payload["cwd"], env=env)
        selector = selectors.DefaultSelector()
        if process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        timeout_value = float(timeout) if timeout is not None else None
        deadline = None if timeout_value is None else timeout_deadline(timeout_value)
        try:
            while selector.get_map():
                self.context.raise_if_cancelled()
                if deadline is not None and timeout_expired(deadline):
                    if timeout_value is None:
                        raise RuntimeError("process timeout deadline set without timeout value")
                    process.kill()
                    raise subprocess.TimeoutExpired(list(normalized), timeout_value)
                for key, _mask in selector.select(timeout=0.1):
                    pipe = cast(Any, key.fileobj)
                    line = pipe.readline()
                    if line:
                        stream = str(key.data)
                        chunk = ProcessChunk(normalized, stream, line, request_id)
                        self.publish_chunk(chunk)
                        yield chunk
                    else:
                        selector.unregister(key.fileobj)
            returncode = process.wait(timeout=0)
        finally:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            selector.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        self.publish_exit(normalized, returncode, request_id)

    def publish_result(self, result: ProcessResult) -> None:
        """Record the process outcome without exposing raw DB operations."""
        if self.context._db is None:
            return
        self.context._db.publish(
            "process.run",
            {
                "argv": list(result.argv),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "ok": result.ok,
                "request_event_id": result.request_event_id,
                "job_id": self.context.job_id,
            },
            "framework",
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def publish_started(self, argv: tuple[str, ...], request_event_id: int | None) -> None:
        """Record that a streamed process was started."""
        if self.context._db is None:
            return
        self.context._db.publish(
            "process.started",
            {
                "argv": list(argv),
                "request_event_id": request_event_id,
                "job_id": self.context.job_id,
            },
            "framework",
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def publish_chunk(self, chunk: ProcessChunk) -> None:
        """Record one streamed process-output chunk."""
        if self.context._db is None:
            return
        self.context._db.publish(
            f"process.{chunk.stream}",
            {
                "argv": list(chunk.argv),
                "stream": chunk.stream,
                "text": chunk.text,
                "request_event_id": chunk.request_event_id,
                "job_id": self.context.job_id,
            },
            "framework",
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def publish_exit(self, argv: tuple[str, ...], returncode: int, request_event_id: int | None) -> None:
        """Record that a streamed process exited."""
        if self.context._db is None:
            return
        self.context._db.publish(
            "process.exited",
            {
                "argv": list(argv),
                "returncode": returncode,
                "ok": returncode == 0,
                "request_event_id": request_event_id,
                "job_id": self.context.job_id,
            },
            "framework",
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )


def normalize_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Validate and normalize an argv sequence for safe process execution."""
    if isinstance(argv, str):
        raise TypeError("process argv must be a sequence of strings, not a shell string")
    normalized = tuple(str(part) for part in argv)
    if not normalized:
        raise ValueError("process argv cannot be empty")
    if any(part == "" for part in normalized):
        raise ValueError("process argv cannot contain empty arguments")
    return normalized


def run_process_argv(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an argv vector with shell execution explicitly disabled."""
    # Framework-mediated argv execution; shell is explicitly disabled.
    return subprocess.run(  # nosec B603
        list(normalize_argv(argv)),
        cwd=str(Path(cwd).expanduser()) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        timeout=timeout,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )


def popen_process_argv(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.Popen[str]:
    """Start an argv-vector process for line-oriented streaming."""
    # Framework-mediated argv execution; shell is explicitly disabled.
    return subprocess.Popen(  # nosec B603
        list(normalize_argv(argv)),
        cwd=str(Path(cwd).expanduser()) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        shell=False,
    )


def timeout_deadline(timeout: float) -> float:
    """Return a monotonic deadline for process streaming timeouts."""
    import time

    return time.monotonic() + timeout


def timeout_expired(deadline: float) -> bool:
    """Return whether a monotonic deadline has passed."""
    import time

    return time.monotonic() >= deadline


@dataclass(slots=True)
class CompletionContext:
    """Lightweight context passed into optional plugin completion hooks."""

    db: EventStore | None = None
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ContextEvents:
    """Capability-aware event API exposed to commandlets.

    This is the preferred plugin-facing abstraction over raw `EventStore`.
    It keeps event reads/writes scoped and auditable while leaving the storage
    implementation free to change behind the API.
    """

    context: CommandContext

    def publish(self, topic: str, payload: dict[str, Any]) -> Event:
        """Publish one event in the current commandlet scope."""
        db = self.require_event_store(f"{self.context.source} event publish")
        self.context.audit_capability(f"db.write:{topic}")
        return db.publish(
            topic,
            payload,
            self.context.source,
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def fetch(
        self,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 100,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> list[Event]:
        """Fetch events by topic with optional run/pipeline scoping."""
        db = self.require_event_store(f"{self.context.source} event fetch")
        for topic in topics:
            self.context.audit_capability(f"db.read:{topic}")
        return db.fetch(
            Subscription(
                topics=topics,
                after_id=after_id,
                limit=limit,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
                parent_command_run_id=parent_command_run_id,
            )
        )

    def query(
        self,
        *,
        topic: str | None = None,
        run: str | None = None,
        pipeline: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        """Query events with optional topic, run, and pipeline filters."""
        db = self.require_event_store(f"{self.context.source} event query")
        self.context.audit_capability(f"db.read:{topic}" if topic else "db.read:*")
        return db.events_matching(
            topic=topic,
            command_run_id=run,
            pipeline_id=pipeline,
            limit=limit,
        )

    def topics(self) -> list[str]:
        """Return known event topics after auditing broad DB read access."""
        db = self.require_event_store(f"{self.context.source} event topics")
        self.context.audit_capability("db.read:*")
        return db.topics()

    def require_event_store(self, label: str) -> EventStore:
        """Return the backing event store without auditing raw DB access."""
        if self.context._db is None:
            raise ValueError(f"{label} requires an active database")
        return self.context._db


class Commandlet(Protocol):
    spec: CommandSpec

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Execute the commandlet and yield payload dictionaries."""
        ...


class CommandletBase:
    """Convenience base class for commandlets that use argparse."""

    spec: CommandSpec

    def parser(self) -> argparse.ArgumentParser:
        """Return an argparse parser named after this commandlet."""
        return argparse.ArgumentParser(prog=self.spec.name)

    def parse_args(self, args: list[str]) -> argparse.Namespace:
        """Parse commandlet arguments with the commandlet parser."""
        return self.parser().parse_args(args)


def command_run_id(context: CommandContext) -> str:
    """Return the current command run ID or a stable interactive fallback."""
    return context.command_run_id or "interactive"


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)


def framework_request_capability(topic: str) -> str | None:
    """Map a framework request topic to the capability it uses."""
    match topic:
        case "framework.console.output.requested":
            return "framework.console.output"
        case "framework.console.alert.requested":
            return "framework.console.alert"
        case "framework.file.page.requested":
            return "framework.file.page"
        case "framework.process.run.requested":
            return "process.run"
        case "framework.process.stream.requested":
            return "process.run"
        case "shell.prompt.requested":
            return "framework.prompt.change"
        case topic if topic.startswith("framework.job."):
            return "framework.job.control"
        case topic if topic.startswith("framework.pipeline."):
            return "framework.pipeline.control"
        case topic if topic.startswith("framework.") and topic.endswith(".requested"):
            return "framework.request"
        case _:
            return None


def capability_declared(capability: str, declarations: Iterable[str]) -> bool:
    """Return whether a capability is exactly declared or covered by a wildcard."""
    for declaration in declarations:
        if capability == declaration:
            return True
        if declaration.endswith(":*") and capability.startswith(declaration[:-1]):
            return True
    return False


def implied_capabilities(spec: CommandSpec) -> tuple[str, ...]:
    """Return capabilities implied by commandlet metadata."""
    capabilities = set(spec.capabilities)
    capabilities.update(f"db.read:{topic}" for topic in spec.consumes)
    capabilities.update(f"db.write:{topic}" for topic in spec.emits)
    return tuple(sorted(capabilities))


def format_table(rows: Sequence[Mapping[str, object] | Sequence[object]], columns: Sequence[str]) -> list[str]:
    """Return aligned text rows for small commandlet tables."""
    values: list[list[str]] = []
    for row in rows:
        if isinstance(row, Mapping):
            values.append([str(row.get(column, "")) for column in columns])
        else:
            values.append([str(row[index]) if index < len(row) else "" for index, _column in enumerate(columns)])
    widths = [
        max(len(column), *(len(row[index]) for row in values))
        for index, column in enumerate(columns)
    ]
    header = "  ".join(column.ljust(widths[index]) for index, column in enumerate(columns))
    divider = "  ".join("-" * width for width in widths)
    body = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in values]
    return [header, divider, *body]
