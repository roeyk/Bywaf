"""Script loading and parsing for REPL resources.

Provides Bywaf script parsing, inline-comment stripping, continuation handling,
and command dispatch for commands loaded from script files.

Used by:
- REPL command handlers: implement `script load file=<path>`.
- CLI startup: runs scripts passed through command-line resource options.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import cast

from ..runner import Runner
from .resource_events import publish_resource_loaded
from .state import ResourceState, default_resource_state


def dispatch_script_command(runner: Runner, command: str, state: ResourceState) -> str | None:
    """Dispatch one script command without importing repl at module load time."""
    from .shell import dispatch_repl_line

    return dispatch_repl_line(runner, command, cast(Any, state))


def repl_line_has_continuation(line: str) -> bool:
    """Return whether a script line has a REPL continuation marker."""
    from .shell import line_has_continuation

    return line_has_continuation(line)


def repl_remove_line_continuation(line: str) -> str:
    """Remove a REPL continuation marker from a script line."""
    from .shell import remove_line_continuation

    return remove_line_continuation(line)


def run_script(runner: Runner, path: Path, state: ResourceState | None = None) -> None:
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
        if dispatch_script_command(runner, command, state) == "exit":
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
        if repl_line_has_continuation(line):
            # Continuations preserve the original starting line number for every
            # command produced by the final logical line.
            buffer.append(repl_remove_line_continuation(line))
            continue
        buffer.append(line)
        logical_line = "\n".join(buffer).strip()
        for command in split_script_command_sequence(logical_line):
            commands.append((start_line, command))
        buffer = []
    if buffer:
        logical_line = "\n".join(buffer).strip()
        for command in split_script_command_sequence(logical_line):
            commands.append((start_line, command))
    return commands


def split_script_command_sequence(line: str) -> list[str]:
    """Split semicolon command sequences while preserving continuation newlines."""
    commands: list[str] = []
    quote: str | None = None
    escaped = False
    current: list[str] = []
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            continue
        if char == ";":
            command = "".join(current).strip()
            if command:
                commands.append(command)
            current = []
            continue
        current.append(char)
    command = "".join(current).strip()
    if command:
        commands.append(command)
    return commands


def strip_inline_comment(line: str) -> str:
    """Remove shell-style `#` comments while preserving quoted or escaped hashes."""
    quote: str | None = None
    chars: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and quote is None and index + 1 < len(line) and line[index + 1] == "#":
            chars.append("#")
            index += 2
            continue
        if char in ("'", '"'):
            quote = None if quote == char else char if quote is None else quote
        if char == "#" and quote is None:
            break
        chars.append(char)
        index += 1
    return "".join(chars)
