"""Subprocess execution helpers for external plugin tools.

Provides process launching, output capture, and result normalization for plugins
that wrap command-line binaries.

Used by:
- wrapper plugins such as nikto, eyewitness, and wireless scanners.
- tests: verify external command error and output handling."""


from __future__ import annotations

import selectors
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .process_audit import audit_process_env
from .process_audit import check_process_argv_for_secrets
from .process_audit import leaked_secret_arguments as leaked_secret_arguments
from .process_audit import redact_known_secret_values
from .process_audit import redact_process_argv
from .process_models import ProcessResult
from .process_stream import (
    ProcessChunk,
    StreamProcessState,
    close_stream_process,
    process_output_selector,
    raise_if_stream_timeout,
    read_stream_chunk,
    timeout_deadline,
    timeout_expired,  # noqa: F401 - re-exported from this module for plugin API compatibility.
)

if TYPE_CHECKING:
    from .context import CommandContext


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
