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

from ..secret.store import REDACTED_VALUE

if TYPE_CHECKING:
    from .context import CommandContext


def check_process_argv_for_secrets(context: CommandContext, argv: tuple[str, ...]) -> None:
    """Warn when resolved in-memory secrets appear in process argv.

    Secrets in argv can be visible to process listings on many systems.  Bywaf
    does not block the execution here, but it records a redacted audit event so
    operators can see that a wrapper plugin passed a secret through an unsafe
    channel.
    """
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
        # Environment variables are usually a better secret channel than argv,
        # but they still need redaction before they enter durable audit events.
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
class StreamProcessState:
    """State needed while streaming one framework-mediated process."""

    normalized_argv: tuple[str, ...]
    audit_argv: tuple[str, ...]
    cwd: str | None
    env: Mapping[str, str] | None
    request_event_id: int | None
    timeout_value: float | None
    deadline: float | None


@dataclass(frozen=True, slots=True)
class ContextProcess:
    """Framework-mediated process API exposed to commandlets.

    Plugins should use this instead of importing `subprocess` directly. The API
    records the request, audits the `framework.process.*` capability, executes
    an argv vector with `shell=False`, and records the result for later
    inspection.
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
        # Publish the request before starting the process.  If execution fails
        # or times out, the audit log still records what was attempted and which
        # commandlet requested it.
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
        if self.context._db is not None:
            # Blocking process wrappers always retain stdout/stderr as an
            # artifact, so enforce the artifact capability before launching.
            self.context.audit_capability("artifact.write")
        completed = run_process_argv(normalized, cwd=payload["cwd"], env=env, timeout=timeout)
        # Store redacted argv in the result object.  Plugin code gets stdout,
        # stderr, and returncode, while audit-safe argv is carried forward to
        # process.run events and exceptions.
        result = ProcessResult(
            argv=audit_argv,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            request_event_id=request.id if request is not None else None,
        )
        artifact_payload = self.attach_output_artifact(result)
        self.publish_result(result, artifact_payload=artifact_payload)
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
        state = self.prepare_stream_process(argv, cwd=cwd, timeout=timeout, env=env)
        self.publish_started(state.audit_argv, state.request_event_id)
        process = popen_process_argv(state.normalized_argv, cwd=state.cwd, env=state.env)
        selector = process_output_selector(process)
        try:
            yield from self.stream_process_chunks(process, selector, state)
            returncode = process.wait(timeout=1)
        finally:
            close_stream_process(process, selector)
        self.publish_exit(state.audit_argv, returncode, state.request_event_id)

    def prepare_stream_process(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None,
        timeout: float | None,
        env: Mapping[str, str] | None,
    ) -> StreamProcessState:
        """Publish stream request metadata and return normalized stream state."""
        normalized = normalize_argv(argv)
        check_process_argv_for_secrets(self.context, normalized)
        audit_argv = redact_process_argv(self.context, normalized)
        cwd_text = str(Path(cwd).expanduser()) if cwd is not None else None
        payload = self.stream_request_payload(audit_argv, cwd_text, timeout, env)
        request = self.context.request("framework.process.stream.requested", payload)
        timeout_value = float(timeout) if timeout is not None else None
        deadline = None if timeout_value is None else timeout_deadline(timeout_value)
        return StreamProcessState(
            normalized_argv=normalized,
            audit_argv=audit_argv,
            cwd=cwd_text,
            env=env,
            request_event_id=request.id if request is not None else None,
            timeout_value=timeout_value,
            deadline=deadline,
        )

    def stream_request_payload(
        self,
        audit_argv: tuple[str, ...],
        cwd: str | None,
        timeout: float | None,
        env: Mapping[str, str] | None,
    ) -> dict[str, Any]:
        """Return audit payload for one streamed process request."""
        payload: dict[str, Any] = {
            "argv": list(audit_argv),
            "cwd": cwd,
            "timeout": timeout,
            "source": self.context.source,
            "command_run_id": self.context.command_run_id,
            "pipeline_id": self.context.pipeline_id,
            "job_id": self.context.job_id,
            "handled": True,
            "mode": "stream",
        }
        audit_env = audit_process_env(self.context, env)
        if audit_env is not None:
            payload.update(audit_env)
        return payload

    def stream_process_chunks(
        self,
        process: subprocess.Popen[str],
        selector: selectors.BaseSelector,
        state: StreamProcessState,
    ) -> Iterable[ProcessChunk]:
        """Yield streamed process chunks until all registered pipes close."""
        while selector.get_map():
            self.context.raise_if_cancelled()
            raise_if_stream_timeout(process, state)
            for key, _mask in selector.select(timeout=0.1):
                chunk = read_stream_chunk(key, state.audit_argv, state.request_event_id)
                if chunk is None:
                    selector.unregister(key.fileobj)
                    continue
                self.publish_chunk(chunk)
                yield chunk

    def attach_output_artifact(self, result: ProcessResult) -> dict[str, Any]:
        """Attach one redacted stdout/stderr transcript artifact for a process run."""
        if self.context._db is None:
            return {}
        transcript = process_output_transcript(self.context, result)
        artifact = self.context.artifacts.attach_text(
            transcript,
            name=process_output_artifact_name(result),
            note="framework-mediated process stdout/stderr",
            content_type="text/plain; charset=utf-8",
        )
        return {
            "artifact_id": artifact.artifact_id,
            "artifact_row_id": artifact.id,
            "artifact_name": artifact.name,
            "artifact_sha256": artifact.sha256,
        }

    def publish_result(self, result: ProcessResult, *, artifact_payload: Mapping[str, Any] | None = None) -> None:
        """Record the process outcome without exposing raw DB operations."""
        if self.context._db is None:
            return
        payload = {
            "argv": list(result.argv),
            "returncode": result.returncode,
            "stdout": redact_known_secret_values(self.context, result.stdout),
            "stderr": redact_known_secret_values(self.context, result.stderr),
            "ok": result.ok,
            "request_event_id": result.request_event_id,
            "job_id": self.context.job_id,
        }
        payload.update(artifact_payload or {})
        self.context._db.publish(
            "process.run",
            payload,
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
                "text": redact_known_secret_values(self.context, chunk.text),
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


def process_output_artifact_name(result: ProcessResult) -> str:
    """Return a stable display name for one process-output transcript artifact."""
    stem = Path(result.argv[0]).name if result.argv else "process"
    request = f"-{result.request_event_id}" if result.request_event_id is not None else ""
    return f"{stem}{request}-output.txt"


def process_output_transcript(context: CommandContext, result: ProcessResult) -> str:
    """Return an audit-safe process transcript suitable for artifact storage."""
    stdout = redact_known_secret_values(context, result.stdout)
    stderr = redact_known_secret_values(context, result.stderr)
    return "\n".join(
        (
            "argv: " + " ".join(result.argv),
            f"returncode: {result.returncode}",
            f"ok: {str(result.ok).lower()}",
            "",
            "stdout:",
            stdout,
            "",
            "stderr:",
            stderr,
        )
    )


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


def process_output_selector(process: subprocess.Popen[str]) -> selectors.BaseSelector:
    """Return a selector registered for one process stdout/stderr pair."""
    selector = selectors.DefaultSelector()
    # Use selectors so stdout and stderr can be streamed without blocking on
    # one pipe while the child is writing to the other.
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    if process.stderr is not None:
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    return selector


def raise_if_stream_timeout(process: subprocess.Popen[str], state: StreamProcessState) -> None:
    """Kill a streaming process and raise when its timeout has expired."""
    if state.deadline is None or not timeout_expired(state.deadline):
        return
    if state.timeout_value is None:
        raise RuntimeError("process timeout deadline set without timeout value")
    process.kill()
    raise subprocess.TimeoutExpired(list(state.normalized_argv), state.timeout_value)


def read_stream_chunk(
    key: selectors.SelectorKey,
    audit_argv: tuple[str, ...],
    request_event_id: int | None,
) -> ProcessChunk | None:
    """Return one streamed chunk, or None when the pipe reached EOF."""
    pipe = cast(Any, key.fileobj)
    line = pipe.readline()
    if not line:
        return None
    # Publish chunks as they arrive so long-running wrapper plugins can expose
    # progress/output before process exit.
    return ProcessChunk(audit_argv, str(key.data), line, request_event_id)


def close_stream_process(process: subprocess.Popen[str], selector: selectors.BaseSelector) -> None:
    """Close stream resources and terminate abandoned child processes."""
    # Always close pipes and the selector. If the generator consumer stops
    # early, terminate the child so process wrappers do not leak subprocesses.
    for pipe in (process.stdout, process.stderr):
        if pipe is not None and not pipe.closed:
            pipe.close()
    selector.close()
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)


def timeout_deadline(timeout: float) -> float:
    """Return a monotonic deadline for process streaming timeouts."""
    return time.monotonic() + timeout


def timeout_expired(deadline: float) -> bool:
    """Return whether a monotonic deadline has passed."""
    return time.monotonic() >= deadline
