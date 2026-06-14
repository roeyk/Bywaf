"""Prompt-toolkit helpers for redacted secret entry.

Provides an interactive `[REDACTED]` input block for explicit secret
assignments while keeping plaintext out of the command buffer.

Used by:
- bywaf.completion: adds secret-aware prompt-toolkit key bindings and styling.
- bywaf.repl.shell: transfers hidden secret values to command dispatch."""

# pyright: reportMissingImports=false, reportGeneralTypeIssues=false
# pyright: reportInvalidTypeForm=false

from __future__ import annotations

from ..askpass import (
    ASKPASS_MODE as ASKPASS_MODE,
    AUTO_SECRET_INPUT_MODE as AUTO_SECRET_INPUT_MODE,
    BLOCK_SECRET_INPUT_MODE as BLOCK_SECRET_INPUT_MODE,
    GETPASS_SECRET_INPUT_MODE as GETPASS_SECRET_INPUT_MODE,
    PLAIN_SECRET_INPUT_MODE as PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE as PLAINTEXT_SECRET_INPUT_MODE,
    desktop_askpass_available as desktop_askpass_available,
)
from .modes import DEFAULT_SECRET_INPUT_MODE as DEFAULT_SECRET_INPUT_MODE
from .modes import SECRET_INPUT_MODES as SECRET_INPUT_MODES
from .modes import SECRET_INPUT_MODE_VAR as SECRET_INPUT_MODE_VAR
from .modes import normalize_secret_input_mode as normalize_secret_input_mode
from .state import SECRET_BLOCK_VALUE as SECRET_BLOCK_VALUE
from .state import PromptSecretInputState as PromptSecretInputState
from .state import PromptSecretSpan as PromptSecretSpan
from .state import open_secret_assignment_name as open_secret_assignment_name
from .prompt import PromptSecretLexer as PromptSecretLexer
from .prompt import SecretCursorOutput as SecretCursorOutput
from .prompt import clear_focused_secret as clear_focused_secret
from .prompt import handle_focused_secret_text as handle_focused_secret_text
from .prompt import handle_secret_backspace as handle_secret_backspace
from .prompt import handle_secret_delete as handle_secret_delete
from .prompt import handle_secret_left as handle_secret_left
from .prompt import handle_secret_right as handle_secret_right
from .prompt import prompt_secret_key_bindings as prompt_secret_key_bindings
from .prompt import prompt_secret_output as prompt_secret_output
from .prompt import prompt_secret_style as prompt_secret_style


def effective_secret_input_mode(value: object | None) -> str:
    """Resolve auto mode using this facade's patchable askpass probe.

    Called by: completion and REPL setup code. Tests patch
    `bywaf.secret.input.desktop_askpass_available`, so this public facade keeps
    the decision point here even though shared constants live in
    `secret.input_modes`.
    """
    mode = normalize_secret_input_mode(value)
    if mode == AUTO_SECRET_INPUT_MODE:
        return ASKPASS_MODE if desktop_askpass_available() else BLOCK_SECRET_INPUT_MODE
    return mode
