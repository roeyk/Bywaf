"""Prompt-toolkit styling and keybindings for the REPL.

Provides prompt input syntax highlighting, secret-input overlay styling, and
completion menu keybindings. Candidate discovery remains in the completion
engine and facade.

Used by:
- bywaf.completion.facade: builds prompt-toolkit sessions.
"""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false

from __future__ import annotations

from typing import Any

try:
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.styles import Style
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    HTML = None
    Lexer = object
    Style = None

from ..secret.input import DEFAULT_SECRET_INPUT_MODE, SECRET_INPUT_MODES, SECRET_INPUT_MODE_VAR, PromptSecretInputState, PromptSecretLexer
from .prompt_keys import (
    COMPLETION_SELECT_KEY_VAR as COMPLETION_SELECT_KEY_VAR,
    COMPLETION_WASD_SELECTION_VAR as COMPLETION_WASD_SELECTION_VAR,
    DEFAULT_COMPLETION_SELECT_KEY as DEFAULT_COMPLETION_SELECT_KEY,
    apply_current_completion as apply_current_completion,
    cancel_completion_menu as cancel_completion_menu,
    completion_key_bindings as completion_key_bindings,
    completion_select_key as completion_select_key,
    completion_select_key_display as completion_select_key_display,
    completion_wasd_selection_enabled as completion_wasd_selection_enabled,
    enter_completion_selection_mode as enter_completion_selection_mode,
    framework_bool as framework_bool,
    merge_prompt_key_bindings as merge_prompt_key_bindings,
    register_select_completion_binding as register_select_completion_binding,
    register_wasd_completion_bindings as register_wasd_completion_bindings,
)


DISPLAY_STYLE_PREFIX = "display/style."
DISPLAY_VALUE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}value"
DISPLAY_STRING_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}string"
DISPLAY_VARIABLE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}variable"

PROMPT_TOOLKIT_COLOR_NAMES = {
    "black": "ansiblack",
    "red": "ansired",
    "green": "ansigreen",
    "yellow": "ansiyellow",
    "blue": "ansiblue",
    "magenta": "ansimagenta",
    "cyan": "ansicyan",
    "white": "ansiwhite",
    "bright-black": "ansibrightblack",
    "bright-red": "ansibrightred",
    "bright-green": "ansibrightgreen",
    "bright-yellow": "ansibrightyellow",
    "bright-blue": "ansibrightblue",
    "bright-magenta": "ansibrightmagenta",
    "bright-cyan": "ansibrightcyan",
    "bright-white": "ansibrightwhite",
}

PROMPT_TOOLKIT_ATTR_NAMES = {
    "bold",
    "italic",
    "underline",
    "reverse",
}


class BywafPromptLexer(Lexer):
    """Style live REPL input without changing command parsing semantics."""

    def __init__(self, completer: Any, secret_state: PromptSecretInputState) -> None:
        self.completer = completer
        self.secret_lexer = PromptSecretLexer(secret_state)

    def lex_document(self, document):
        secret_get_line = self.secret_lexer.lex_document(document)

        def get_line(lineno: int):
            fragments = prompt_value_fragments(self.completer, document.lines[lineno])
            return overlay_secret_fragments(fragments, secret_get_line(lineno))

        return get_line


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
            append_variable_reference_fragments(fragments, text[index:], variable_style)
            break
        append_assignment_key_fragments(fragments, text[index:equals], variable_style)
        fragments.append(("", "="))
        value_end = value_token_end(text, equals + 1)
        value_text = text[equals + 1:value_end]
        if value_text.startswith(("'", '"')):
            quote_end = prompt_closing_quote_index(value_text, 0)
            styled_len = len(value_text) if quote_end is None else quote_end + 1
            if styled_len:
                quote_allows_variables = value_text.startswith('"')
                if quote_allows_variables:
                    append_styled_value_fragments(
                        fragments,
                        value_text[:styled_len],
                        string_style or value_style,
                        variable_style,
                    )
                else:
                    fragments.append((string_style or value_style, value_text[:styled_len]))
            if styled_len < len(value_text):
                append_styled_value_fragments(fragments, value_text[styled_len:], value_style, variable_style)
        else:
            append_styled_value_fragments(fragments, value_text, value_style, variable_style)
        index = value_end
    return [fragment for fragment in fragments if fragment[1]]


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
    index = 0
    while index < len(text):
        dollar = next_variable_reference_start(text, index)
        if dollar is None:
            fragments.append((value_style, text[index:]))
            break
        fragments.append((value_style, text[index:dollar]))
        end = variable_reference_end(text, dollar + 1)
        fragments.append((variable_style, text[dollar:end]))
        index = end


def append_assignment_key_fragments(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append text before `=`, styling only the assignment key token."""
    if not variable_style:
        append_variable_reference_fragments(fragments, text, variable_style)
        return
    key_start = assignment_key_start(text)
    append_variable_reference_fragments(fragments, text[:key_start], variable_style)
    fragments.append((variable_style, text[key_start:]))


def assignment_key_start(text: str) -> int:
    """Return the token start for the key immediately before an equals sign."""
    index = len(text)
    while index > 0 and not text[index - 1].isspace():
        index -= 1
    return index


def append_variable_reference_fragments(fragments: list[tuple[str, str]], text: str, variable_style: str) -> None:
    """Append plain text while styling `$VAR` references when configured."""
    if not variable_style:
        fragments.append(("", text))
        return
    index = 0
    while index < len(text):
        dollar = next_variable_reference_start(text, index)
        if dollar is None:
            fragments.append(("", text[index:]))
            break
        fragments.append(("", text[index:dollar]))
        end = variable_reference_end(text, dollar + 1)
        fragments.append((variable_style, text[dollar:end]))
        index = end


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


def overlay_secret_fragments(base_fragments: list[tuple[str, str]], secret_fragments: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Let secret-span styling override value/string styling."""
    secret_style_by_index: dict[int, str] = {}
    position = 0
    for style, text in secret_fragments:
        if style:
            for offset in range(len(text)):
                secret_style_by_index[position + offset] = style
        position += len(text)
    if not secret_style_by_index:
        return base_fragments
    merged: list[tuple[str, str]] = []
    position = 0
    for style, text in base_fragments:
        for char in text:
            final_style = secret_style_by_index.get(position, style)
            if merged and merged[-1][0] == final_style:
                merged[-1] = (final_style, f"{merged[-1][1]}{char}")
            else:
                merged.append((final_style, char))
            position += 1
    return merged


def prompt_input_style():
    """Return prompt-toolkit style classes used by secret-input rendering."""
    if Style is None:
        return None
    return Style.from_dict(
        {
            "secret.focused": "bg:ansired #ffffff blink bold",
            "secret.inactive": "bg:#5f0000 #ffffff",
        }
    )


def prompt_fragment_style(style: str) -> str:
    """Translate Bywaf display-style tokens into prompt-toolkit fragments."""
    parts: list[str] = []
    for token in style.split():
        normalized = token.strip().casefold().replace("_", "-")
        if not normalized:
            continue
        if normalized in PROMPT_TOOLKIT_ATTR_NAMES:
            parts.append(normalized)
        elif normalized in {"dim", "blink", "strikethrough"}:
            continue
        elif normalized in PROMPT_TOOLKIT_COLOR_NAMES:
            parts.append(PROMPT_TOOLKIT_COLOR_NAMES[normalized])
        elif normalized.startswith("#") and len(normalized) in {4, 7}:
            parts.append(normalized)
        elif normalized.startswith("rgb:"):
            hex_color = rgb_style_to_hex(normalized)
            if hex_color:
                parts.append(hex_color)
    return " ".join(parts)


def rgb_style_to_hex(token: str) -> str | None:
    """Convert `rgb:R,G,B` into a prompt-toolkit hex color."""
    try:
        values = [int(part.strip()) for part in token.removeprefix("rgb:").split(",")]
    except ValueError:
        return None
    if len(values) != 3 or any(value < 0 or value > 255 for value in values):
        return None
    return "#" + "".join(f"{value:02x}" for value in values)


def secret_input_mode(completer: Any) -> str:
    """Return the configured secret input method."""
    value = completer.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE)
    mode = str(value or DEFAULT_SECRET_INPUT_MODE).strip().casefold()
    return mode if mode in SECRET_INPUT_MODES else DEFAULT_SECRET_INPUT_MODE


def secret_input_bottom_toolbar(secret_state: PromptSecretInputState):
    """Show secret-block instructions only while the block is focused."""
    if HTML is None or secret_state.focused() is None:
        return None
    return HTML("<b>Secret:</b> type value | <b>Tab</b> accepts | <b>Esc</b> leaves | <b>Enter</b> submits")
