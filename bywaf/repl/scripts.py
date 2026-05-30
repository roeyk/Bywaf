"""Script loading and parsing for REPL resources.

Provides Bywaf script parsing, inline-comment stripping, continuation handling,
and command dispatch for commands loaded from script files.

Used by:
- REPL command handlers: implement `script load file=<path>`.
- CLI startup: runs scripts passed through command-line resource options.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any
from typing import Callable
from typing import cast

from ..runner import Runner
from .parsing import line_has_continuation, remove_line_continuation, split_command_sequence, strip_inline_comment
from .resource_events import publish_resource_loaded
from .state import ResourceState, default_resource_state

ScriptDispatcher = Callable[[Runner, str, ResourceState], str | None]


def dispatch_script_command(
    runner: Runner,
    command: str,
    state: ResourceState,
    dispatcher: ScriptDispatcher | None = None,
) -> str | None:
    """Dispatch one script command."""
    dispatcher = dispatcher or default_script_dispatcher()
    return dispatcher(runner, command, state)


def default_script_dispatcher() -> ScriptDispatcher:
    """Return the normal REPL dispatcher without a module-level dependency."""
    dispatch = importlib.import_module(".dispatch", __package__)

    def call_dispatch(runner: Runner, command: str, state: ResourceState) -> str | None:
        return dispatch.dispatch_repl_line(runner, command, cast(Any, state))

    return call_dispatch


def run_script(
    runner: Runner,
    path: Path,
    state: ResourceState | None = None,
    dispatcher: ScriptDispatcher | None = None,
) -> None:
    """Run one command expression per non-comment script line."""
    state = state or default_resource_state(runner)
    commands = script_commands(path)
    event = publish_resource_loaded(
        runner,
        "script",
        path=path,
        details={"commands": len(commands)},
    )
    serial = str(event.payload["serial"])
    print(f"loaded script={path} serial={serial}")
    for line_number, command in commands:
        # Each script command is audited before execution so partial script runs
        # can be reconstructed even if a later command fails or exits.
        runner.events.publish(
            "resource.script.command",
            {
                "serial": serial,
                "resource_type": "script",
                "path": str(path),
                "line": line_number,
                "command": command,
            },
            "framework",
        )
        print(f"{path}:{line_number}: {command}")
        if dispatch_script_command(runner, command, state, dispatcher) == "exit":
            return


def script_commands(path: Path) -> list[tuple[int, str]]:
    """Parse a Bywaf script file into `(line_number, command)` tuples."""
    commands: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = strip_inline_comment(raw_line).rstrip()
        if not buffer and not line.strip():
            continue
        if not buffer:
            start_line = line_number
        if line_has_continuation(line):
            # Continuations preserve the original starting line number for every
            # command produced by the final logical line.
            buffer.append(remove_line_continuation(line))
            continue
        buffer.append(line)
        logical_line = "\n".join(buffer).strip()
        for command in split_command_sequence(logical_line, split_newlines=False):
            commands.append((start_line, command))
        buffer = []
    if buffer:
        logical_line = "\n".join(buffer).strip()
        for command in split_command_sequence(logical_line, split_newlines=False):
            commands.append((start_line, command))
    return commands
