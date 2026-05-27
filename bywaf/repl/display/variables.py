"""Variable, secret, subject, and expansion display helpers.

Provides color-aware variable rows, secret redaction labels, subject-based text
styling, and optional variable-expansion previews.

Used by:
- repl.commands: display `set` output and expansion previews.
- event/report renderers: style subject-tagged payload values."""

from __future__ import annotations

import re
import sys

from ...runner import Runner
from ...secret.store import SECRET_REF_PREFIX
from ...style import ansi_color, subject_style
from .settings import (
    DEFAULT_VAR_COLOR_MODE,
    DEFAULT_VAR_NAME_COLOR,
    DEFAULT_VAR_VALUE_COLOR,
    DISPLAY_EXPANSION_DEFAULT,
    DISPLAY_EXPANSION_VAR,
    VAR_COLOR_MODE_VAR,
    VAR_NAME_COLOR_VAR,
    VAR_VALUE_COLOR_VAR,
)

def display_var_value(runner: Runner, value: str) -> str:
    """Return a variable value with in-memory secret references redacted."""
    secret_ref = runner.registry.secrets.metadata(value)
    if secret_ref is None:
        if value.startswith(SECRET_REF_PREFIX):
            # A secret ref may exist in persisted config before the cleartext has
            # been hydrated into this process.
            return redacted_secret_text("unavailable")
        return value
    return redacted_secret_text(secret_ref.fingerprint.format())


def format_var_assignment(runner: Runner, name: str, value: str, *, prefix: str = "") -> str:
    """Return a `name=value` variable row with optional ANSI color."""
    displayed_value = display_var_value(runner, value)
    if not vars_color_enabled(runner):
        return f"{prefix}{name}={displayed_value}"
    name_color = runner.registry.varstore.get(VAR_NAME_COLOR_VAR, DEFAULT_VAR_NAME_COLOR) or DEFAULT_VAR_NAME_COLOR
    value_color = runner.registry.varstore.get(VAR_VALUE_COLOR_VAR, DEFAULT_VAR_VALUE_COLOR) or DEFAULT_VAR_VALUE_COLOR
    return f"{prefix}{ansi_color(name, name_color)}={ansi_var_value(displayed_value, value_color)}"


def vars_color_enabled(runner: Runner) -> bool:
    """Return whether variable listings should include ANSI color escapes."""
    mode = (runner.registry.varstore.get(VAR_COLOR_MODE_VAR, DEFAULT_VAR_COLOR_MODE) or DEFAULT_VAR_COLOR_MODE).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def subject_text(runner: Runner | None, subject: str, value: object) -> str:
    """Render a value using a user-configured display style for its subject."""
    text = str(value)
    if runner is None:
        return text
    style = subject_style(runner.registry.varstore.get, subject)
    if not style:
        return text
    return ansi_color(text, style)


def display_expansion_preview(runner: Runner, expanded_command: str, *, changed: bool) -> None:
    """Print an optional expanded command preview for REPL built-ins."""
    mode = expansion_display_mode(runner)
    if mode == "off" or (mode == "changed" and not changed):
        return
    print(f"expanded: {redact_expanded_command_text(runner, expanded_command)}")


def redact_expanded_command_text(runner: Runner, text: str) -> str:
    """Replace in-memory secret handles in preview text with redacted labels."""
    redacted = text
    for secret_ref in sorted(runner.registry.secrets.refs.values(), key=lambda item: len(item.ref), reverse=True):
        redacted = redacted.replace(secret_ref.ref, redacted_secret_label(runner, secret_ref.fingerprint.format()))
    return re.sub(
        rf"{re.escape(SECRET_REF_PREFIX)}[A-Za-z0-9_]+",
        redacted_secret_label(runner, "unavailable"),
        redacted,
    )


def redacted_secret_label(runner: Runner, fingerprint: str) -> str:
    """Return a redacted secret label with provenance metadata."""
    if not vars_color_enabled(runner):
        return redacted_secret_text(fingerprint)
    return ansi_secret_redaction(redacted_secret_text(fingerprint))


def redacted_secret_text(fingerprint: str) -> str:
    """Return the display token for one redacted secret."""
    return f"[REDACTED#{display_fingerprint_token(fingerprint)}]"


def display_fingerprint_token(fingerprint: str) -> str:
    """Return the compact digest part of a secret fingerprint."""
    return fingerprint.rsplit(":", 1)[-1]


def expansion_display_mode(runner: Runner) -> str:
    """Return normalized command expansion preview mode."""
    value = runner.registry.varstore.get(DISPLAY_EXPANSION_VAR, DISPLAY_EXPANSION_DEFAULT)
    mode = str(value or DISPLAY_EXPANSION_DEFAULT).strip().casefold()
    if mode in {"off", "changed", "on"}:
        return mode
    return DISPLAY_EXPANSION_DEFAULT


def ansi_var_value(text: str, color: str) -> str:
    """Wrap variable values, giving redacted secrets a warning-style badge."""
    if not text.startswith("[REDACTED"):
        return ansi_color(text, color)
    return ansi_secret_redaction(text)


def ansi_secret_redaction(text: str) -> str:
    """Render redacted secret text as white on a dark red background."""
    return f"\x1b[37;48;5;52m{text}\x1b[0m"
