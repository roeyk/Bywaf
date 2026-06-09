"""Prompt input fragment styling façade.

Used by: `prompt_ui` and tests as the stable import point for prompt scanning,
value rendering, style translation, and secret-overlay helpers.
"""

from __future__ import annotations

from .prompt_scanner import (
    is_variable_reference_char as is_variable_reference_char,
    next_unquoted_equals as next_unquoted_equals,
    next_variable_reference_start as next_variable_reference_start,
    prompt_closing_quote_index as prompt_closing_quote_index,
    value_token_end as value_token_end,
    variable_reference_end as variable_reference_end,
)
from .prompt_secret_overlay import overlay_secret_fragments as overlay_secret_fragments
from .prompt_styles import (
    DISPLAY_STRING_STYLE_VAR as DISPLAY_STRING_STYLE_VAR,
    DISPLAY_STYLE_PREFIX as DISPLAY_STYLE_PREFIX,
    DISPLAY_VALUE_STYLE_VAR as DISPLAY_VALUE_STYLE_VAR,
    DISPLAY_VARIABLE_STYLE_VAR as DISPLAY_VARIABLE_STYLE_VAR,
    PROMPT_TOOLKIT_ATTR_NAMES as PROMPT_TOOLKIT_ATTR_NAMES,
    PROMPT_TOOLKIT_COLOR_NAMES as PROMPT_TOOLKIT_COLOR_NAMES,
    prompt_fragment_style as prompt_fragment_style,
    rgb_style_to_hex as rgb_style_to_hex,
)
from .prompt_value_render import (
    append_assignment_key_fragments as append_assignment_key_fragments,
    append_quoted_value_fragments as append_quoted_value_fragments,
    append_styled_value_fragments as append_styled_value_fragments,
    append_variable_reference_fragments as append_variable_reference_fragments,
    assignment_key_start as assignment_key_start,
    prompt_value_fragments as prompt_value_fragments,
)

__all__ = [
    "DISPLAY_STRING_STYLE_VAR",
    "DISPLAY_STYLE_PREFIX",
    "DISPLAY_VALUE_STYLE_VAR",
    "DISPLAY_VARIABLE_STYLE_VAR",
    "PROMPT_TOOLKIT_ATTR_NAMES",
    "PROMPT_TOOLKIT_COLOR_NAMES",
    "append_assignment_key_fragments",
    "append_quoted_value_fragments",
    "append_styled_value_fragments",
    "append_variable_reference_fragments",
    "assignment_key_start",
    "is_variable_reference_char",
    "next_unquoted_equals",
    "next_variable_reference_start",
    "overlay_secret_fragments",
    "prompt_closing_quote_index",
    "prompt_fragment_style",
    "prompt_value_fragments",
    "rgb_style_to_hex",
    "value_token_end",
    "variable_reference_end",
]
