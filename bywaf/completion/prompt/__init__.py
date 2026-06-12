"""Prompt-toolkit styling and keybindings for the REPL.

Provides prompt input syntax highlighting, secret-input overlay styling, and
completion menu keybindings. Candidate discovery remains in the completion
engine and facade.

Used by:
- bywaf.completion.facade: builds prompt-toolkit sessions.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
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

from ...secret.input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_INPUT_MODE_VAR,
    PromptSecretInputState,
    PromptSecretLexer,
    effective_secret_input_mode,
    normalize_secret_input_mode,
)
from .fragments import (
    DISPLAY_STRING_STYLE_VAR as DISPLAY_STRING_STYLE_VAR,
    DISPLAY_STYLE_PREFIX as DISPLAY_STYLE_PREFIX,
    DISPLAY_VALUE_STYLE_VAR as DISPLAY_VALUE_STYLE_VAR,
    DISPLAY_VARIABLE_STYLE_VAR as DISPLAY_VARIABLE_STYLE_VAR,
    PROMPT_TOOLKIT_ATTR_NAMES as PROMPT_TOOLKIT_ATTR_NAMES,
    PROMPT_TOOLKIT_COLOR_NAMES as PROMPT_TOOLKIT_COLOR_NAMES,
    append_assignment_key_fragments as append_assignment_key_fragments,
    append_quoted_value_fragments as append_quoted_value_fragments,
    append_styled_value_fragments as append_styled_value_fragments,
    append_var_refs as append_var_refs,
    assignment_key_start as assignment_key_start,
    is_variable_reference_char as is_variable_reference_char,
    next_unquoted_equals as next_unquoted_equals,
    next_variable_reference_start as next_variable_reference_start,
    overlay_secret_fragments as overlay_secret_fragments,
    prompt_closing_quote_index as prompt_closing_quote_index,
    prompt_fragment_style as prompt_fragment_style,
    prompt_value_fragments as prompt_value_fragments,
    rgb_style_to_hex as rgb_style_to_hex,
    value_token_end as value_token_end,
    variable_reference_end as variable_reference_end,
)
from .keys import (
    COMPLETION_SELECT_KEY_VAR as COMPLETION_SELECT_KEY_VAR,
    COMPLETION_WASD_SELECTION_VAR as COMPLETION_WASD_SELECTION_VAR,
    DEFAULT_COMPLETION_SELECT_KEY as DEFAULT_COMPLETION_SELECT_KEY,
    apply_current_completion as apply_current_completion,
    cancel_completion_menu as cancel_completion_menu,
    completion_key_bindings as completion_key_bindings,
    completion_select_key as completion_select_key,
    completion_select_key_display as completion_select_key_display,
    wasd_selection_enabled as wasd_selection_enabled,
    enter_completion_selection_mode as enter_completion_selection_mode,
    framework_bool as framework_bool,
    merge_prompt_key_bindings as merge_prompt_key_bindings,
    register_select_binding as register_select_binding,
    register_wasd_bindings as register_wasd_bindings,
)


class BywafPromptLexer(Lexer):
    """Style live REPL input without changing command parsing semantics."""

    def __init__(self, completer: Any, secret_state: PromptSecretInputState) -> None:
        self.completer = completer
        self.secret_lexer = PromptSecretLexer(secret_state)

    def lex_document(self, document):
        """Implement lex document for this module."""
        secret_get_line = self.secret_lexer.lex_document(document)

        def get_line(lineno: int):
            fragments = prompt_value_fragments(self.completer, document.lines[lineno])
            return overlay_secret_fragments(fragments, secret_get_line(lineno))

        return get_line


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


def secret_input_mode(completer: Any) -> str:
    """Return the configured secret input method."""
    value = completer.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE)
    return normalize_secret_input_mode(value)


def prompt_secret_mode(completer: Any) -> str:
    """Return the secret input method active for the current environment."""
    value = completer.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE)
    return effective_secret_input_mode(value)


def secret_input_bottom_toolbar(secret_state: PromptSecretInputState):
    """Show secret-block instructions only while the block is focused."""
    if HTML is None or secret_state.focused() is None:
        return None
    return HTML("<b>Secret:</b> type value | <b>Tab</b> accepts | <b>Esc</b> leaves | <b>Enter</b> submits")
