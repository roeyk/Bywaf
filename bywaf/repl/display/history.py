"""Command history display helpers.

Provides timestamp normalization, filtering, and color-aware rendering for REPL
history entries.

Used by:
- repl.commands: implement `history` listing.
- tests: verify script-friendly history output remains stable."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from ...runner import Runner
from ...style import ansi_color
from ...time_format import normalize_history_ts
from .settings import (
    DEFAULT_HISTORY_COLOR_MODE,
    DEFAULT_HISTORY_TIMESTAMP_COLOR,
    DISPLAY_COMMENT_STYLE_VAR,
    HISTORY_COLOR_MODE_VAR,
    HISTORY_TIMESTAMP_COLOR_VAR,
)

def print_history(
    entries: Sequence[str] = (),
    selectors: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> None:
    """Print the current session history, optionally filtered by time bounds."""
    window = history_time_window(selectors or {})
    for entry in entries:
        if history_entry_in_window(entry, window):
            print(format_history_entry(entry, runner))


def format_history_entry(entry: str, runner: Runner | None = None) -> str:
    """Display script-friendly history as timestamp-first for readability."""
    command, separator, timestamp = entry.rpartition("  # ")
    if not separator or not timestamp:
        return entry
    display_timestamp = normalize_history_ts(timestamp)
    comment_style = runner.registry.varstore.get(DISPLAY_COMMENT_STYLE_VAR, "") if runner is not None else ""
    if runner is not None and comment_style:
        display_timestamp = ansi_color(display_timestamp, comment_style)
    elif runner is not None and history_color_enabled(runner):
        color = (
            runner.registry.varstore.get(HISTORY_TIMESTAMP_COLOR_VAR, DEFAULT_HISTORY_TIMESTAMP_COLOR)
            or DEFAULT_HISTORY_TIMESTAMP_COLOR
        )
        display_timestamp = ansi_color(display_timestamp, color)
    return f"{display_timestamp}  {command}"


def history_color_enabled(runner: Runner) -> bool:
    """Return whether history listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(HISTORY_COLOR_MODE_VAR, DEFAULT_HISTORY_COLOR_MODE) or DEFAULT_HISTORY_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def history_time_window(selectors: dict[str, str]) -> tuple[str | None, str | None]:
    """Convert history selectors to inclusive compact timestamp bounds."""
    # Bounds compare as YYYYMMDDHHMMSS strings, which preserves chronological
    # order without needing timezone reconstruction for history comments.
    since = normalize_history_time_bound(selectors["since"], until=False) if "since" in selectors else None
    until = normalize_history_time_bound(selectors["until"], until=True) if "until" in selectors else None
    return since, until


def normalize_history_time_bound(value: str, *, until: bool) -> str:
    """Normalize `yyyymmdd[HH[MM[SS]]]` or `time:<...>` to YYYYMMDDHHMMSS."""
    if ":" in value:
        kind, raw = value.split(":", 1)
        if kind != "time":
            raise ValueError("history since=/until= only supports time bounds")
    else:
        raw = value
    digits = "".join(char for char in raw if char.isdigit())
    if len(digits) not in {8, 10, 12, 14}:
        raise ValueError("history time must be yyyymmdd[HH[MM[SS]]]")
    if len(digits) == 8:
        return digits + ("235959" if until else "000000")
    if len(digits) == 10:
        return digits + ("5959" if until else "0000")
    if len(digits) == 12:
        return digits + ("59" if until else "00")
    return digits


def history_entry_in_window(entry: str, window: tuple[str | None, str | None]) -> bool:
    """Return whether a script-friendly history entry falls within a time window."""
    since, until = window
    _command, separator, timestamp = entry.rpartition("  # ")
    if not separator:
        return since is None and until is None
    compact = "".join(char for char in timestamp if char.isdigit())
    if len(compact) < 14:
        return since is None and until is None
    compact = compact[:14]
    return (since is None or compact >= since) and (until is None or compact <= until)
