"""Subprocess execution helpers for external plugin tools.

Provides process launching, output capture, and result normalization for plugins
that wrap command-line binaries.

Used by:
- wrapper plugins such as nikto, eyewitness, and wireless scanners.
- tests: verify external command error and output handling."""


from __future__ import annotations

import selectors
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .secrets import REDACTED_VALUE

if TYPE_CHECKING:
    from .plugin import CommandContext


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
    return tuple(redact_known_secret_values(context, arg) for arg in argv)


def redact_known_secret_values(context: CommandContext, text: str) -> str:
    """Replace known plaintext secret values with the canonical redaction token."""
    value = text
    for ref in context._secrets.refs:
        secret = context._secrets.get(ref)
        if secret:
            value = value.replace(secret, REDACTED_VALUE)
    return value


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
                secrets.append(
                    {
                        "env": str(key),
                        "name": secret_ref.name,
                        "fingerprint": secret_ref.fingerprint.format(),
                    }
                )
        value = redact_known_secret_values(context, value)
        redacted[str(key)] = value
    return {"env": redacted, "secrets": secrets}


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
    return time.monotonic() + timeout


def timeout_expired(deadline: float) -> bool:
    """Return whether a monotonic deadline has passed."""
    return time.monotonic() >= deadline
