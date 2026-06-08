"""Pipeline-level command syntax helpers."""

from __future__ import annotations

import shlex


def split_pipeline_raw(command_line: str) -> tuple[list[str], bool]:
    """Split a pipeline without changing quote context inside each stage."""
    command_line, background = peel_pipeline_background(command_line)
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
        # This is a tiny shell-like scanner.  We cannot split on every `|`
        # because URLs, regexes, and shell snippets may contain quoted pipes
        # that belong to a commandlet argument.
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "|":
            part = command_line[start:index].strip()
            if part:
                parts.append(part)
            start = index + 1
    final = command_line[start:].strip()
    if final:
        parts.append(final)
    return parts, background


def peel_pipeline_background(command_line: str) -> tuple[str, bool]:
    """Remove a trailing standalone `&` from a full pipeline expression."""
    stripped = command_line.rstrip()
    if not stripped.endswith("&"):
        return command_line, False
    amp_index = len(stripped) - 1
    if amp_index == 0 or not stripped[amp_index - 1].isspace():
        return command_line, False
    if is_quoted_position(stripped, amp_index):
        return command_line, False
    return stripped[:amp_index].rstrip(), True


def is_quoted_position(text: str, position: int) -> bool:
    """Return whether one character index is inside shell-style quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if index == position:
            return quote is not None
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
    return False


def peel_pipeline_name_prefix(command_line: str) -> tuple[str, str | None]:
    """Remove a leading `pipeline name: command` prefix when present."""
    index = find_pipeline_name_colon(command_line)
    if index is None:
        return command_line, None
    display_name = normalize_final_text(command_line[:index])
    command = command_line[index + 1:].strip()
    if not display_name or not command:
        return command_line, None
    return command, display_name


def find_pipeline_name_colon(command_line: str) -> int | None:
    """Find a top-level naming colon followed by whitespace before any pipe."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "|":
            return None
        if char == ":" and index + 1 < len(command_line) and command_line[index + 1].isspace():
            return index
    return None


def normalize_final_text(raw_value: str) -> str:
    """Return selector text with shell quotes removed when possible."""
    stripped = raw_value.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    return " ".join(tokens)
