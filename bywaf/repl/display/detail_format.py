"""Formatting helpers for detailed event inspection.

Used by: `repl.display.detail` and `repl.display.detail_context` while
rendering `event <id>` output.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any

from ...runner import Runner
from ...style import ansi_color
from ...time_format import format_operator_timestamp
from .settings import (
    DEFAULT_EVENT_COLOR_MODE,
    DEFAULT_EVENT_KEY_COLOR,
    EVENT_COLOR_MODE_VAR,
    EVENT_COMMANDLET_COLOR,
    EVENT_HEADING_KEY_COLOR,
    EVENT_HEADING_VALUE_COLOR,
    EVENT_KEY_COLOR_VAR,
)


def format_event_timestamp(value: datetime) -> str:
    """Render full event time in the operator's local timezone."""
    return format_operator_timestamp(value)


def format_event_heading(runner: Runner, event_id: int | None) -> str:
    """Return the highlighted detail heading for one event.

    Called by: `print_event_info()` before the event sections.
    """
    if not event_color_enabled(runner):
        return f"Event ID: {event_id}"
    return (
        f"{ansi_color('Event ID', EVENT_HEADING_KEY_COLOR)}: "
        f"{ansi_color(str(event_id), EVENT_HEADING_VALUE_COLOR)}"
    )


def format_event_kv(runner: Runner, key: str, value: object, *, prefix: str = "") -> str:
    """Return an event detail key/value row with optional colored keys."""
    if not event_color_enabled(runner):
        return f"{prefix}{key}: {value}"
    key_color = (
        runner.registry.varstore.get(EVENT_KEY_COLOR_VAR, DEFAULT_EVENT_KEY_COLOR)
        or DEFAULT_EVENT_KEY_COLOR
    )
    return f"{prefix}{ansi_color(key, key_color)}: {format_event_value(key, value)}"


def format_event_value(key: str, value: object) -> str:
    """Return special value styling for event detail fields."""
    text = str(value)
    if key.casefold() == "commandlet":
        return ansi_color(text, EVENT_COMMANDLET_COLOR)
    return text


def format_event_section_header(runner: Runner, label: str) -> str:
    """Return a highlighted section header for event detail output."""
    if not event_color_enabled(runner):
        return f"{label}:"
    return f"{ansi_color(label, EVENT_HEADING_KEY_COLOR)}:"


def event_color_enabled(runner: Runner) -> bool:
    """Return whether event detail listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(EVENT_COLOR_MODE_VAR, DEFAULT_EVENT_COLOR_MODE)
        or DEFAULT_EVENT_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def format_payload_value(value: Any) -> str:
    """Render nested payload values without a one-line raw dict dump."""
    if isinstance(value, list | tuple):
        return ", ".join(format_payload_value(item) for item in value)
    if isinstance(value, dict):
        # Sort nested keys so event detail output remains stable across Python
        # versions and plugin payload construction order.
        return ", ".join(
            f"{key}={format_payload_value(value[key])}" for key in sorted(value)
        )
    return str(value)
