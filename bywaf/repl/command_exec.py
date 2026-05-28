"""REPL execution helpers for commandlets and explicit shell commands.

Provides the `run` built-in, explicit `exec` OS-command support, and the
commandlet event echo policy used after foreground commandlet execution.

Used by:
- bywaf.repl.commands: wires handlers into the built-in dispatch table.
- bywaf.repl.shell: falls through unknown built-ins to commandlet execution.
"""

from __future__ import annotations

import shlex
import subprocess
from typing import TYPE_CHECKING, Any

from ..framework_requests import process_framework_requests
from ..runner import Runner
from .display import print_events, print_help

if TYPE_CHECKING:
    from .shell import ShellState


SUPPRESSED_COMMANDLET_OUTPUT_TOPICS = {"framework.file.page.requested", "report.rendered"}
def handle_run_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Execute the active commandlet context."""
    del line
    if rest is not None:
        print("usage: run")
        return None
    if not state.active_context:
        print("no active commandlet; use <commandlet> first")
        return None
    # `run` is a convenience for the active `use` context. It does not create a
    # new command syntax path; direct commandlet invocation remains primary.
    execute_repl_commandlet(runner, state, state.active_context)
    return None


def handle_exec_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Execute an operating-system command."""
    del state, line
    if rest is None:
        print_help(runner, "exec")
    else:
        execute_shell_command(runner, rest)
    return None


def execute_repl_commandlet(runner: Runner, state: ShellState, command: str) -> None:
    """Run a commandlet line and print emitted events."""
    original_db = runner.db
    events = runner.execute(command)
    if runner.db is not original_db:
        reset_framework_request_cursor(state)
    process_framework_requests(runner, state)
    # Some commandlets emit audit events after also requesting formatted console
    # output. Keep those events in storage, but avoid echoing raw payloads in
    # the REPL after the operator-facing renderer has already printed.
    print_events(visible_commandlet_events(events), runner)


def visible_commandlet_events(events: list[Any]) -> list[Any]:
    """Return commandlet events that should be echoed after execution."""
    return [event for event in events if event.topic not in SUPPRESSED_COMMANDLET_OUTPUT_TOPICS]


def reset_framework_request_cursor(state: ShellState) -> None:
    """Reset REPL request tracking after switching to a different database."""
    state.framework_request_after_id = 0
    state.handled_request_ids.clear()


def execute_shell_command(runner: Runner, command: str) -> int:
    """Run an OS command argv and audit its lifecycle."""
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if not argv:
        print_help(runner, "exec")
        return 2
    # Shell execution is intentionally explicit through `exec`; normal commandlet
    # execution remains the default REPL behavior.
    started = runner.events.publish(
        "shell.exec.started",
        {"command": command, "argv": argv},
        "framework",
    )
    completed = subprocess.run(argv, check=False)
    topic = "shell.exec.completed" if completed.returncode == 0 else "shell.exec.failed"
    runner.events.publish(
        topic,
        {
            "command": command,
            "argv": argv,
            "returncode": completed.returncode,
            "ok": completed.returncode == 0,
            "request_event_id": started.id,
        },
        "framework",
    )
    return completed.returncode
