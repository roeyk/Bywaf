"""Secret-input mode selection helpers.

Used by: setup, REPL variable commands, and prompt UI setup to normalize the
configured secret input mode before choosing askpass, block input, getpass, or
plain-text fallbacks.
"""

from __future__ import annotations

from .askpass import (
    ASKPASS_MODE,
    AUTO_SECRET_INPUT_MODE,
    BLOCK_SECRET_INPUT_MODE,
    GETPASS_SECRET_INPUT_MODE,
    PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE,
    desktop_askpass_available,
)

SECRET_INPUT_MODE_VAR = "secret.input-mode"
DEFAULT_SECRET_INPUT_MODE = AUTO_SECRET_INPUT_MODE
SECRET_INPUT_MODES = {
    ASKPASS_MODE,
    AUTO_SECRET_INPUT_MODE,
    BLOCK_SECRET_INPUT_MODE,
    GETPASS_SECRET_INPUT_MODE,
    PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE,
}


def normalize_secret_input_mode(value: object | None) -> str:
    """Return a supported secret input mode, defaulting to auto."""
    mode = str(value or DEFAULT_SECRET_INPUT_MODE).strip().casefold()
    return mode if mode in SECRET_INPUT_MODES else DEFAULT_SECRET_INPUT_MODE


def effective_secret_input_mode(value: object | None) -> str:
    """Resolve auto mode to askpass on desktops and block elsewhere."""
    mode = normalize_secret_input_mode(value)
    if mode == AUTO_SECRET_INPUT_MODE:
        return ASKPASS_MODE if desktop_askpass_available() else BLOCK_SECRET_INPUT_MODE
    return mode
