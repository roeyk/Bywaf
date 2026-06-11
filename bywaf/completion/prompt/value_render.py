"""Prompt input value-fragment construction.

Used by: `completion.prompt.BywafPromptLexer` to style assignment keys, quoted strings,
plain values, and `$variable` references in live REPL input.
"""

from __future__ import annotations

from typing import Any

from .scanner import (
    next_unquoted_equals,
    next_variable_reference_start,
    prompt_closing_quote_index,
    value_token_end,
    variable_reference_end,
)
from .styles import (
    DISPLAY_STRING_STYLE_VAR,
    DISPLAY_VALUE_STYLE_VAR,
    DISPLAY_VARIABLE_STYLE_VAR,
    prompt_fragment_style,
)


def prompt_value_fragments(completer: Any, text: str):
    """Return prompt-toolkit fragments for variables, values, and quoted strings."""
    variable_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_VARIABLE_STYLE_VAR, ""))
    value_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_VALUE_STYLE_VAR, ""))
    string_style = prompt_fragment_style(completer.registry.varstore.get(DISPLAY_STRING_STYLE_VAR, ""))
    if not variable_style and not value_style and not string_style:
        return [("", text)]
    fragments: list[tuple[str, str]] = []
    index = 0
    while index < len(text):
        equals = next_unquoted_equals(text, index)
        if equals is None:
            append_var_refs(fragments, text[index:], variable_style)
            break
        append_assignment_key_fragments(fragments, text[index:equals], variable_style)
        fragments.append(("", "="))
        value_end = value_token_end(text, equals + 1)
        value_text = text[equals + 1:value_end]
        append_value_fragments(fragments, value_text, value_style, string_style, variable_style)
        index = value_end
    return [fragment for fragment in fragments if fragment[1]]


def append_value_fragments(
    fragments: list[tuple[str, str]],
    value_text: str,
    value_style: str,
    string_style: str,
    variable_style: str,
) -> None:
    """Append one assignment value using quoted or unquoted styling rules."""
    if value_text.startswith(("'", '"')):
        append_quoted_value_fragments(fragments, value_text, value_style, string_style, variable_style)
    else:
        append_styled_value_fragments(fragments, value_text, value_style, variable_style)


def append_quoted_value_fragments(
    fragments: list[tuple[str, str]],
    value_text: str,
    value_style: str,
    string_style: str,
    variable_style: str,
) -> None:
    """Append a quoted value token and style any trailing unquoted suffix."""
    quote_end = prompt_closing_quote_index(value_text, 0)
    styled_len = len(value_text) if quote_end is None else quote_end + 1
    if styled_len:
        quote_style = string_style or value_style
        if value_text.startswith('"'):
            append_styled_value_fragments(fragments, value_text[:styled_len], quote_style, variable_style)
        else:
            fragments.append((quote_style, value_text[:styled_len]))
    if styled_len < len(value_text):
        append_styled_value_fragments(fragments, value_text[styled_len:], value_style, variable_style)


def append_styled_value_fragments(
    fragments: list[tuple[str, str]],
    text: str,
    value_style: str,
    variable_style: str,
) -> None:
    """Append a value token, letting `$VAR` references override value styling."""
    if not variable_style:
        fragments.append((value_style, text))
        return
    append_var_styled_text(fragments, text, base_style=value_style, variable_style=variable_style)


def append_assignment_key_fragments(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append text before `=`, styling only the assignment key token."""
    if not variable_style:
        append_var_refs(fragments, text, variable_style)
        return
    key_start = assignment_key_start(text)
    append_var_refs(fragments, text[:key_start], variable_style)
    fragments.append((variable_style, text[key_start:]))


def assignment_key_start(text: str) -> int:
    """Return the token start for the key immediately before an equals sign."""
    index = len(text)
    while index > 0 and not text[index - 1].isspace():
        index -= 1
    return index


def append_var_refs(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append plain text while styling `$VAR` references when configured."""
    if not variable_style:
        fragments.append(("", text))
        return
    append_var_styled_text(fragments, text, base_style="", variable_style=variable_style)


def append_var_styled_text(
    fragments: list[tuple[str, str]],
    text: str,
    *,
    base_style: str,
    variable_style: str,
) -> None:
    """Append text spans, overriding base style for `$VAR` references."""
    index = 0
    while index < len(text):
        dollar = next_variable_reference_start(text, index)
        if dollar is None:
            fragments.append((base_style, text[index:]))
            break
        fragments.append((base_style, text[index:dollar]))
        end = variable_reference_end(text, dollar + 1)
        fragments.append((variable_style, text[dollar:end]))
        index = end
