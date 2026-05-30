"""REPL command-line parsing helpers.

Provides comment stripping, command sequence splitting, continuation handling,
and argv remainder reconstruction shared by interactive shell and scripts.

Used by:
- repl.shell: read interactive command lines.
- repl.scripts: parse script files without importing shell orchestration.
- CLI compatibility exports: preserve public helper functions.
"""

from __future__ import annotations

import shlex


def split_command_sequence(line: str, *, split_newlines: bool = True) -> list[str]:
    """Split command sequences while preserving quoted separators."""
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
        if char == ";" or (split_newlines and char == "\n"):
            # Only unquoted semicolons and newlines delimit REPL commands.
            # This makes multi-line paste behave like a tiny script without
            # making commandlet parsers handle unrelated trailing commands.
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


def line_has_continuation(line: str) -> bool:
    """Return whether a physical line ends with an unescaped continuation slash."""
    stripped = line.rstrip()
    backslashes = len(stripped) - len(stripped.rstrip("\\"))
    return backslashes % 2 == 1


def remove_line_continuation(line: str) -> str:
    """Remove one trailing continuation slash from a physical line."""
    stripped = line.rstrip()
    return stripped[:-1]


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


def command_from_remainder(tokens: list[str]) -> str:
    """Build a command string from argparse REMAINDER tokens.

    A single token is already a shell-preserved command string, which matters
    for quoted pipelines such as `bywaf exec 'a | b'`.
    """
    if not tokens:
        raise ValueError("exec requires a command")
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(shlex.quote(token) for token in tokens)
