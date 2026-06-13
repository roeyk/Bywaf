"""Secret handling helpers for REPL variable commands.

Used by: `repl.command.vars.set_var()` when the operator passes `--secret`.
"""

from __future__ import annotations

import getpass
import sys

from ....runner import Runner
from ....secret.askpass import (
    ASKPASS_MODE,
    AskpassCancelled,
    AskpassUnavailable,
    PLAIN_SECRET_INPUT_MODE,
    PLAINTEXT_SECRET_INPUT_MODE,
    read_askpass_secret,
)
from ....secret.input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_INPUT_MODES,
    SECRET_INPUT_MODE_VAR,
    effective_secret_input_mode,
    normalize_secret_input_mode,
)


def configured_secret_input_mode(runner: Runner) -> str:
    """Return the configured secret input mode from the variable store.

    Called by: `set_var()` before prompting for an empty secret value.
    """
    return runner.registry.varstore.get(SECRET_INPUT_MODE_VAR, DEFAULT_SECRET_INPUT_MODE) or DEFAULT_SECRET_INPUT_MODE


def read_secret_value(name: str, *, mode: str | None = None) -> str:
    """Read one secret value without echoing it to the terminal.

    Called by: `set_var()` when explicit secret storage needs interactive
    input.
    """
    prompt = f"Secret for {name}: "
    warn_unknown_secret_mode(mode)
    configured_mode = normalize_secret_input_mode(mode)
    effective_mode = effective_secret_input_mode(mode)
    if effective_mode == ASKPASS_MODE:
        try:
            return read_askpass_secret(prompt)
        except AskpassCancelled as exc:
            raise ValueError("secret prompt cancelled") from exc
        except AskpassUnavailable as exc:
            if configured_mode in {DEFAULT_SECRET_INPUT_MODE, ASKPASS_MODE}:
                print(
                    f"warning: askpass secret input unavailable ({exc}); falling back to terminal prompt",
                    file=sys.stderr,
                )
                return getpass.getpass(prompt)
            raise ValueError("askpass secret input is unavailable") from exc
    if effective_mode in {PLAIN_SECRET_INPUT_MODE, PLAINTEXT_SECRET_INPUT_MODE}:
        return input(prompt)
    return getpass.getpass(prompt)


def warn_unknown_secret_mode(mode: str | None) -> None:
    """Warn when a configured secret input mode is unsupported.

    Called by: `read_secret_value()` before applying fallback behavior.
    """
    normalized = str(mode or DEFAULT_SECRET_INPUT_MODE).strip().casefold()
    if normalized not in SECRET_INPUT_MODES:
        print(
            "warning: unsupported input mode; falling back to auto",
            file=sys.stderr,
        )
