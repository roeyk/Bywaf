"""Streaming subprocess helpers for framework-mediated process execution.

Used by:
- plugin authors, command contexts, plugin checks, and runner commandlet execution.
"""

from __future__ import annotations

import selectors
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast


@dataclass(frozen=True, slots=True)
class ProcessChunk:
    """One streamed stdout/stderr chunk from a framework-mediated process.

    This represents incremental process output before the process exits.
    Constructed by: `read_stream_chunk()` while `stream_process()` is active.
    Used by: wrapper plugins consuming `ContextProcess.stream()`.
    """

    argv: tuple[str, ...]
    stream: str
    text: str
    request_event_id: int | None = None


@dataclass(frozen=True, slots=True)
class StreamProcessState:
    """State needed while streaming one framework-mediated process.

    This represents stable execution metadata for one streaming child process.
    Constructed by: `stream_process()`.
    Used by: `raise_if_stream_timeout()`, `read_stream_chunk()`, and cleanup
    helpers.
    """

    normalized_argv: tuple[str, ...]
    audit_argv: tuple[str, ...]
    cwd: str | None
    env: Mapping[str, str] | None
    request_event_id: int | None
    timeout_value: float | None
    deadline: float | None


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
