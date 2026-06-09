"""History recording and redaction for REPL commands.

Used by:
- `repl.shell.repl`: records each interactive command after redacting obvious
  secret assignments.
- resource/history tests: verify saved session history remains script-friendly.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..secret.store import load_or_create_fingerprint_key, redact_command_text
from .resource_specs import DEFAULT_HISTORY
from .state import DEFAULT_HISTORY_TIMESTAMP_FORMAT

HISTORY_SECRET_NAMES = frozenset(
    {
        "api-key",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "client-secret",
        "client_secret",
        "cookie",
        "key",
        "pass",
        "password",
        "secret",
        "session",
        "token",
    }
)


def record_command_history(
    history_command: str,
    path: Path = DEFAULT_HISTORY,
    session_history: list[str] | None = None,
    timestamp_format: str = DEFAULT_HISTORY_TIMESTAMP_FORMAT,
) -> str | None:
    """Append a history-safe command to in-memory session history.

    Called by: `repl.shell.repl` after each logical command line.
    Used for: retaining script-friendly session history without writing every
    command immediately to disk.
    """
    del path
    if not history_command.strip():
        return None
    # Store the timestamp as an inline comment so explicitly saved history
    # remains readable as executable scripts after stripping comments.
    timestamp = datetime.now().astimezone().strftime(timestamp_format).strip()
    entry = f"{history_command}  # {timestamp}"
    if session_history is not None:
        session_history.append(entry)
    return entry


def redact_history_command(command: str) -> str:
    """Return a history-safe command with obvious secret assignments removed.

    Called by: `repl.shell.repl` before recording command history.
    Used for: keeping accidental `password=...` and token-like values out of
    saved history while preserving non-secret commands unchanged.
    """
    if "=" not in command:
        return command
    result = redact_command_text(command, key=load_or_create_fingerprint_key(), secret_names=HISTORY_SECRET_NAMES)
    return result.command
