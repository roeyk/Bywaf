"""Prompt input token scanning helpers.

Used by: `prompt.value_render` and the prompt package façade to find key/value
boundaries, quoted strings, and Bywaf variable references without changing
command parsing semantics.
"""

from __future__ import annotations


def next_variable_reference_start(text: str, start: int) -> int | None:
    """Return the next unescaped `$` that begins a variable reference."""
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "$" and index + 1 < len(text) and is_variable_reference_char(text[index + 1]):
            return index
        index += 1
    return None


def variable_reference_end(text: str, start: int) -> int:
    """Return the end of a `$VAR` reference."""
    index = start
    while index < len(text) and is_variable_reference_char(text[index]):
        index += 1
    return index


def is_variable_reference_char(char: str) -> bool:
    """Return whether a character can appear in a Bywaf variable reference."""
    return char.isalnum() or char in {"_", "-", ".", "/"}


def next_unquoted_equals(text: str, start: int) -> int | None:
    """Return the next equals sign outside shell-style quotes."""
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "=":
            return index
    return None


def value_token_end(text: str, start: int) -> int:
    """Return the end of the key=value value token."""
    quote = ""
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char.isspace():
            break
        index += 1
    return index


def prompt_closing_quote_index(text: str, start: int) -> int | None:
    """Return the matching prompt quote index, ignoring escaped quotes."""
    quote = text[start]
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index
    return None
