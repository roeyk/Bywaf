"""Plugin protocol and shared dataclasses."""

from __future__ import annotations

import argparse
import selectors
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from .artifacts import Artifact, artifact_store_for_event_store
from .db import EventStore, Subscription
from .events import Event
from .rendering import Column, Table, render_console_table
from .secrets import InMemorySecretStore
from .specs import (
    ArgumentSpec,
    CommandSpec,
    CompletionSpec,
    OptionSpec,
    PlanItem,
    PlanRepair,
    PlanReport,
    TriggerSpec,
)
from .stores import ArtifactStoreProtocol, EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol
from .varstore import ScopedVarStore, VarStore


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
    secret: bool = False,
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
                secret,
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
    _vars: ScopedVarStore
    _secrets: InMemorySecretStore
    metadata: dict[str, Any]

    def __init__(
        self,
        db: EventStore | None,
        source: str,
        _varstore: VarStore | None = None,
        _secrets: InMemorySecretStore | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Create a command context while preserving the public `db=` keyword."""
        self._db = db
        self.source = source
        self.metadata = metadata or {}
        self._vars = ScopedVarStore(
            _varstore or VarStore(),
            self.source,
            self.metadata.get("run_vars", {}),
        )
        self._secrets = _secrets or InMemorySecretStore()

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
        return self._vars

    @property
    def secrets(self) -> "ContextSecrets":
        """Return the mediated secret resolver for opaque secret references."""
        return ContextSecrets(self)

    @property
    def events(self) -> "ContextEvents":
        """Return the mediated event-bus API for plugin code."""
        return ContextEvents(self)

    @property
    def process(self) -> "ContextProcess":
        """Return the mediated process-execution API for plugin code."""
        return ContextProcess(self)

    @property
    def artifacts(self) -> "ContextArtifacts":
        """Return the mediated artifact API for plugin code."""
        return ContextArtifacts(self)

    @property
    def render(self) -> "ContextRender":
        """Return the mediated rendering API for plugin code."""
        return ContextRender(self)

    @property
    def signals(self) -> "ContextSignals":
        """Return live-control signals addressed to this commandlet run."""
        return ContextSignals(self)

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
    def note(self) -> str | None:
        """Return the framework-level `note=` text for this command run."""
        value = self.metadata.get("note")
        return str(value) if value is not None else None

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

    def event_store(self, label: str | None = None) -> EventStoreProtocol:
        """Return the event/audit store without exposing raw DB maintenance."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires an active event store")
        return self._db

    def runtime_store(self, label: str | None = None) -> RuntimeStoreProtocol:
        """Return runtime metadata storage for jobs, runs, and pipelines."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active runtime storage")
        return self._db

    def maintenance_store(self, label: str | None = None) -> MaintenanceStoreProtocol:
        """Return privileged storage-maintenance operations."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active storage maintenance")
        self.audit_capability("db.raw")
        return self._db

    def artifact_store(self, label: str | None = None) -> ArtifactStoreProtocol:
        """Return the paired artifact store for framework/internal commandlets."""
        if self._db is None:
            raise ValueError(f"{label or self.source} requires active artifact storage")
        return artifact_store_for_event_store(self._db)

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

    def table(
        self,
        rows: Iterable[Mapping[str, object] | Sequence[object]],
        columns: Sequence[str | Column] | None = None,
        *,
        title: str | None = None,
    ) -> None:
        """Render a structured table through the framework output path."""
        self.render.table(Table.from_rows(rows, columns, title=title))

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

    def progress_started(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-started event."""
        return self.progress(
            status="started",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress(
        self,
        *,
        phase: str,
        status: str = "updated",
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit a structured progress event subject to framework throttling."""
        payload = progress_payload(
            self,
            status=status,
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            extra=extra,
        )
        return self.publish_progress_payload(payload)

    def progress_completed(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-completed event."""
        return self.progress(
            status="completed",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress_failed(
        self,
        *,
        phase: str,
        message: str | None = None,
        error: str | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-failed event."""
        payload_extra = dict(extra)
        if error is not None:
            payload_extra["error"] = error
        payload = progress_payload(
            self,
            status="failed",
            phase=phase,
            current=None,
            total=None,
            unit=None,
            message=message,
            target=None,
            eta_seconds=None,
            extra=payload_extra,
        )
        return self.publish_progress_payload(payload)

    def publish_progress_payload(self, payload: Mapping[str, object]) -> Event | None:
        """Publish one progress payload after applying throttle policy."""
        if not should_emit_progress(self, payload):
            return None
        if self._db is None:
            return None
        status = str(payload.get("status", "updated"))
        self.audit_capability("plugin.progress")
        event = self._db.publish(
            f"plugin.progress.{status}",
            dict(payload),
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        self.metadata["_progress_last"] = {
            "monotonic": time.monotonic(),
            "phase": payload.get("phase"),
            "percent": payload.get("percent"),
            "status": status,
        }
        return event

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

    def page_text(self, text: object, *, suffix: str = ".txt") -> None:
        """Page generated text through the same framework path as local files."""
        content = str(text)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as handle:
            handle.write(content)
            if content and not content.endswith("\n"):
                handle.write("\n")
            path = Path(handle.name)
        payload = {
            "path": str(path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
            "temporary": True,
        }
        if self.request("framework.file.page.requested", payload) is None:
            try:
                print(path.read_text(errors="replace"), end="", flush=True)
            finally:
                path.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class ContextSecrets:
    """Narrow secret-resolution API exposed to commandlets."""

    context: CommandContext

    def resolve(self, value: str | None, default: str | None = None) -> str | None:
        """Resolve an opaque secret reference, or pass through normal text."""
        if value is None or value == "":
            return default
        secret = self.context._secrets.get(value)
        if secret is None:
            return value
        self.context.audit_capability("framework.secret.resolve")
        return secret

    def fingerprint(self, value: str | None) -> str | None:
        """Return an audit-safe fingerprint for an opaque secret reference."""
        metadata = self.context._secrets.metadata(value or "")
        return metadata.fingerprint.format() if metadata is not None else None

    def is_secret_ref(self, value: str | None) -> bool:
        """Return whether a value is an in-memory secret reference."""
        return self.context._secrets.is_ref(value)


def check_process_argv_for_secrets(context: CommandContext, argv: tuple[str, ...]) -> None:
    """Warn when resolved in-memory secrets appear in process argv."""
    leaked = leaked_secret_arguments(context, argv)
    if not leaked:
        return
    context.audit_capability("framework.secret.argv")
    if context._db is not None:
        context._db.publish(
            "process.secret.argv",
            {
                "argv": list(redact_process_argv(context, argv)),
                "secret_fingerprints": leaked,
                "job_id": context.job_id,
            },
            "framework",
            pipeline_id=context.pipeline_id,
            command_run_id=context.command_run_id,
            parent_command_run_id=context.parent_command_run_id,
        )


def leaked_secret_arguments(context: CommandContext, argv: tuple[str, ...]) -> list[dict[str, str]]:
    """Return metadata for in-memory secrets that appear in argv text."""
    found: list[dict[str, str]] = []
    for ref, secret_ref in context._secrets.refs.items():
        secret = context._secrets.get(ref)
        if secret and any(secret in arg for arg in argv):
            found.append({"name": secret_ref.name, "fingerprint": secret_ref.fingerprint.format()})
    return found


def redact_process_argv(context: CommandContext, argv: tuple[str, ...]) -> tuple[str, ...]:
    """Redact any known secret values before argv is written to audit events."""
    redacted: list[str] = []
    for arg in argv:
        value = arg
        for ref in context._secrets.refs:
            secret = context._secrets.get(ref)
            if secret:
                value = value.replace(secret, "<redacted>")
        redacted.append(value)
    return tuple(redacted)


def audit_process_env(context: CommandContext, env: Mapping[str, str] | None) -> dict[str, Any] | None:
    """Return redacted process environment details for audit events."""
    if env is None:
        return None
    redacted: dict[str, str] = {}
    secrets: list[dict[str, str]] = []
    for key, raw_value in sorted(env.items()):
        value = str(raw_value)
        for ref, secret_ref in context._secrets.refs.items():
            secret = context._secrets.get(ref)
            if secret and secret in value:
                value = value.replace(secret, "<redacted>")
                secrets.append(
                    {
                        "env": str(key),
                        "name": secret_ref.name,
                        "fingerprint": secret_ref.fingerprint.format(),
                    }
                )
        redacted[str(key)] = value
    return {"env": redacted, "secrets": secrets}


@dataclass(frozen=True, slots=True)
class ContextRender:
    """Framework-mediated rendering API exposed to commandlets."""

    context: CommandContext

    def table(self, table: Table) -> Event | None:
        """Request rendering of one structured table."""
        payload = {
            **table.to_payload(),
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "row_count": len(table.rows),
        }
        event = self.context.request("framework.render.table.requested", payload)
        if event is None:
            rendered = render_console_table(table)
            if rendered:
                print(rendered, flush=True)
        return event


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
        check_process_argv_for_secrets(self.context, normalized)
        audit_argv = redact_process_argv(self.context, normalized)
        audit_env = audit_process_env(self.context, env)
        payload: dict[str, Any] = {
            "argv": list(audit_argv),
            "cwd": str(Path(cwd).expanduser()) if cwd is not None else None,
            "timeout": timeout,
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "handled": True,
        }
        if audit_env is not None:
            payload.update(audit_env)
        request = self.context.request("framework.process.run.requested", payload)
        completed = run_process_argv(normalized, cwd=payload["cwd"], env=env, timeout=timeout)
        result = ProcessResult(
            argv=audit_argv,
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
        check_process_argv_for_secrets(self.context, normalized)
        audit_argv = redact_process_argv(self.context, normalized)
        audit_env = audit_process_env(self.context, env)
        payload: dict[str, Any] = {
            "argv": list(audit_argv),
            "cwd": str(Path(cwd).expanduser()) if cwd is not None else None,
            "timeout": timeout,
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "handled": True,
            "mode": "stream",
        }
        if audit_env is not None:
            payload.update(audit_env)
        request = self.context.request("framework.process.stream.requested", payload)
        request_id = request.id if request is not None else None
        self.publish_started(audit_argv, request_id)
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
                        chunk = ProcessChunk(audit_argv, stream, line, request_id)
                        self.publish_chunk(chunk)
                        yield chunk
                    else:
                        selector.unregister(key.fileobj)
            returncode = process.wait(timeout=1)
        finally:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            selector.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        self.publish_exit(audit_argv, returncode, request_id)

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


def progress_payload(
    context: CommandContext,
    *,
    status: str,
    phase: str,
    current: int | float | None,
    total: int | float | None,
    unit: str | None,
    message: str | None,
    target: str | None,
    eta_seconds: int | float | None,
    extra: Mapping[str, object],
) -> dict[str, object]:
    """Build one normalized progress payload."""
    payload: dict[str, object] = {
        "commandlet": context.source,
        "status": status,
        "phase": phase,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "parent_command_run_id": context.parent_command_run_id,
    }
    if current is not None:
        payload["current"] = current
    if total is not None:
        payload["total"] = total
    percent = progress_percent(current, total)
    if percent is not None:
        payload["percent"] = percent
    if unit is not None:
        payload["unit"] = unit
    if message is not None:
        payload["message"] = message
    if target is not None:
        payload["target"] = target
    if eta_seconds is not None:
        payload["eta_seconds"] = eta_seconds
    payload.update(extra)
    return payload


def progress_percent(current: int | float | None, total: int | float | None) -> float | None:
    """Return progress percent when current and total are usable."""
    if current is None or total is None or total <= 0:
        return None
    return round((float(current) / float(total)) * 100, 2)


def should_emit_progress(context: CommandContext, payload: Mapping[str, object]) -> bool:
    """Enforce framework progress throttling for one command run."""
    status = str(payload.get("status", "updated"))
    if status in {"started", "completed", "failed"}:
        return True
    last = context.metadata.get("_progress_last")
    if not isinstance(last, Mapping):
        return True
    phase = payload.get("phase")
    if phase != last.get("phase"):
        return True
    interval_ms = progress_float_var(context, "progress.min-interval-ms", 250.0)
    last_time = last.get("monotonic")
    if isinstance(last_time, (int, float)) and (time.monotonic() - float(last_time)) * 1000 >= interval_ms:
        return True
    percent = payload.get("percent")
    last_percent = last.get("percent")
    if isinstance(percent, (int, float)) and isinstance(last_percent, (int, float)):
        delta = progress_float_var(context, "progress.min-percent-delta", 1.0)
        return abs(float(percent) - float(last_percent)) >= delta
    return False


def progress_float_var(context: CommandContext, name: str, default: float) -> float:
    """Read a global progress throttle setting with a safe fallback."""
    raw = context.vars.get_global(name, str(default))
    try:
        return float(raw) if raw is not None else default
    except ValueError:
        return default


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

    def follow(
        self,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 100,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
        until_parent_done: bool = False,
        idle_interval: float = 1.0,
        timeout: float | None = None,
    ) -> Iterable[Event]:
        """Yield matching events until cancellation, timeout, or parent completion.

        This is for finite second-stage listeners in pipelines. When
        `until_parent_done` is true, the stream exits after the parent command
        run has completed or failed and all matching events have been drained.
        Long-running service plugins should leave `until_parent_done` false and
        use cancellation/signals or their own stop condition.
        """
        cursor = after_id
        scoped_pipeline = pipeline_id if pipeline_id is not None else self.context.pipeline_id
        scoped_run = command_run_id
        if scoped_run is None and until_parent_done:
            scoped_run = self.context.parent_command_run_id
        deadline = None if timeout is None or timeout <= 0 else time.monotonic() + timeout
        while True:
            if self.context.cancelled():
                return
            events = self.fetch(
                topics,
                after_id=cursor,
                limit=limit,
                pipeline_id=scoped_pipeline,
                command_run_id=scoped_run,
                parent_command_run_id=parent_command_run_id,
            )
            if events:
                cursor = max(event.id or cursor for event in events)
                yield from events
                continue
            if until_parent_done and self.command_run_terminal(scoped_run):
                return
            if deadline is not None and time.monotonic() >= deadline:
                return
            sleep_for = idle_interval
            if deadline is not None:
                sleep_for = min(sleep_for, max(0.0, deadline - time.monotonic()))
            time.sleep(max(0.0, sleep_for))

    def command_run_terminal(self, command_run_id: str | None) -> bool:
        """Return whether a command run has reached a terminal lifecycle event."""
        if command_run_id is None:
            return False
        db = self.require_event_store(f"{self.context.source} event follow")
        self.context.audit_capability("db.read:command.run.completed")
        self.context.audit_capability("db.read:command.run.failed")
        return bool(
            db.events_matching(topic="command.run.completed", command_run_id=command_run_id, limit=1)
            or db.events_matching(topic="command.run.failed", command_run_id=command_run_id, limit=1)
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


@dataclass(frozen=True, slots=True)
class ContextSignals:
    """Plugin-facing helper for framework live-control signals."""

    context: CommandContext

    def pending(self, *, action: str | None = None, after_id: int = 0, limit: int = 1000) -> list[Event]:
        """Return signals that apply to this job, pipeline, or run."""
        events = self.context.events.query(topic="runtime.signal.requested", limit=limit)
        matching = [
            event
            for event in events
            if (event.id or 0) > after_id
            and signal_applies_to_context(event, self.context)
            and (action is None or event.payload.get("action") == action)
        ]
        return matching

    def applied(self, request: Event, message: str = "", **details: object) -> Event:
        """Publish that this commandlet applied a live-control signal."""
        return self._respond("runtime.signal.applied", request, message, details)

    def ignored(self, request: Event, message: str = "", **details: object) -> Event:
        """Publish that this commandlet ignored a live-control signal."""
        return self._respond("runtime.signal.ignored", request, message, details)

    def _respond(self, topic: str, request: Event, message: str, details: dict[str, object]) -> Event:
        payload = {
            "request_event_id": request.id,
            "action": request.payload.get("action"),
            "message": message,
            "details": details,
        }
        return self.context.events.publish(topic, payload)


def signal_applies_to_context(event: Event, context: CommandContext) -> bool:
    """Return whether one runtime signal is scoped to this command context."""
    target_type = event.payload.get("target_type")
    target_id = str(event.payload.get("target_id", ""))
    return (
        (target_type == "run" and context.command_run_id == target_id)
        or (target_type == "pipeline" and context.pipeline_id == target_id)
        or (target_type == "job" and context.job_id is not None and str(context.job_id) == target_id)
    )


@dataclass(frozen=True, slots=True)
class ContextArtifacts:
    """Framework-mediated artifact API exposed to commandlets."""

    context: CommandContext

    def attach_file(
        self,
        path: str | Path,
        *,
        name: str | None = None,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> Artifact:
        """Attach one file to the paired artifact store and audit it."""
        db = self.require_event_store("artifact attach")
        self.context.audit_capability("filesystem.read")
        self.context.audit_capability("artifact.write")
        artifact = artifact_store_for_event_store(db).attach_file(
            Path(path),
            name=name,
            note=note,
            commandlet=self.context.source,
            job_id=job_id if job_id is not None else self.context.job_id,
            pipeline_id=pipeline_id if pipeline_id is not None else self.context.pipeline_id,
            command_run_id=command_run_id if command_run_id is not None else self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )
        self.publish_attached(artifact)
        return artifact

    def attach_files(
        self,
        paths: Iterable[str | Path],
        *,
        note: str | None = None,
        job_id: int | str | None = None,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
    ) -> list[Artifact]:
        """Attach several files to the same run/job/pipeline provenance."""
        return [
            self.attach_file(
                path,
                note=note,
                job_id=job_id,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
            )
            for path in paths
        ]

    def publish_attached(self, artifact: Artifact) -> Event | None:
        """Record artifact provenance in the main event database."""
        if self.context._db is None:
            return None
        payload = artifact_event_payload(artifact)
        return self.context._db.publish(
            "artifact.attached",
            payload,
            "framework",
            pipeline_id=artifact.pipeline_id,
            command_run_id=artifact.command_run_id,
            parent_command_run_id=artifact.parent_command_run_id,
        )

    def require_event_store(self, label: str) -> EventStore:
        """Return the backing event store without exposing raw DB writes."""
        if self.context._db is None:
            raise ValueError(f"{label} requires an active database")
        return self.context._db


def artifact_event_payload(artifact: Artifact) -> dict[str, Any]:
    """Return the main-DB audit payload for one artifact row."""
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_row_id": artifact.id,
        "name": artifact.name,
        "content_type": artifact.content_type,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "created_at": artifact.created_at,
        "source_path": artifact.source_path,
        "commandlet": artifact.commandlet,
        "job_id": artifact.job_id,
        "pipeline_id": artifact.pipeline_id,
        "command_run_id": artifact.command_run_id,
        "parent_command_run_id": artifact.parent_command_run_id,
        "note": artifact.note,
    }


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

    def var_default(
        self,
        context: CommandContext,
        name: str,
        default: Any = None,
        *,
        cast=None,
        empty_is_none: bool = True,
    ) -> Any:
        """Return a commandlet variable value for use as an argparse default.

        This implements the Bywaf precedence rule: explicit CLI arguments
        override parser defaults, commandlet variables override code defaults,
        and code defaults are used last.
        """
        value = context.vars.get(name)
        if value is None or (empty_is_none and value == ""):
            return default
        if cast is None:
            return value
        try:
            return cast(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid value for {context.source}.{name}: {value}") from exc

    def values_or_var(
        self,
        context: CommandContext,
        values: Sequence[str],
        name: str,
        *,
        required: bool = False,
    ) -> list[str]:
        """Return CLI positional values or a split commandlet variable."""
        if values:
            return list(values)
        stored = context.vars.get(name)
        if stored:
            parsed = split_var_values(stored)
            if parsed:
                return parsed
        if required:
            raise ValueError(f"{self.spec.name} requires {name} argument or {context.source}.{name} variable")
        return []


def split_var_values(value: str) -> list[str]:
    """Split comma and whitespace separated variable values."""
    return [part for chunk in value.split(",") for part in chunk.split() if part]


def command_run_id(context: CommandContext) -> str:
    """Return the current command run ID or a stable interactive fallback."""
    return context.command_run_id or "interactive"


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)


def framework_request_capability(topic: str) -> str | None:
    """Map a framework request topic to the capability it uses."""
    exact = framework_request_capability_map().get(topic)
    if exact is not None:
        return exact
    for prefix, capability in framework_request_prefix_capabilities().items():
        if topic.startswith(prefix):
            return capability
    if topic.startswith("framework.") and topic.endswith(".requested"):
        return "framework.request"
    return None


def framework_request_capability_map() -> dict[str, str]:
    """Return exact framework request topic capability mappings."""
    return {
        "framework.console.output.requested": "framework.console.output",
        "framework.console.alert.requested": "framework.console.alert",
        "framework.file.page.requested": "framework.file.page",
        "framework.process.run.requested": "process.run",
        "framework.process.stream.requested": "process.run",
        "framework.render.table.requested": "framework.render.table",
        "shell.prompt.requested": "framework.prompt.change",
    }


def framework_request_prefix_capabilities() -> dict[str, str]:
    """Return prefix-based framework request capability mappings."""
    return {
        "plugin.progress.": "plugin.progress",
        "framework.job.": "framework.job.control",
        "framework.pipeline.": "framework.pipeline.control",
    }


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
    rendered = render_console_table(Table.from_rows(rows, columns))
    return rendered.splitlines() if rendered else []
