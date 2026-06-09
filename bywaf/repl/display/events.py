"""Compact event display rendering.

Provides one-line event rows and event-specific syntax styling.

Used by:
- repl.commands: implement `events` and compact topic listings.
- shell helpers: show commandlet output events after non-REPL calls."""

from __future__ import annotations

from ...runner import Runner
from ...style import ansi_color
from .detail import event_color_enabled
from .event_rows import format_event
from .settings import (
    DISPLAY_STRING_STYLE_VAR,
    EVENT_COMMANDLET_COLOR,
    EVENT_ID_COLOR,
)


def friendly_error(exc: Exception) -> str:
    """Normalize exception text for REPL display."""
    if isinstance(exc, KeyError):
        return str(exc).strip("'")
    return str(exc)


def print_events(events, runner: Runner | None = None) -> None:
    """Print persisted events in a compact inspectable form."""
    for event in events:
        print(format_event_listing_line(runner, event, format_event(event, runner)))


def format_event_listing_line(runner: Runner | None, event, line: str) -> str:
    """Color a compact event row using configured event and subject styles."""
    if runner is None:
        return line
    if not event_color_enabled(runner):
        return style_quoted_strings(runner, line)
    event_id, separator, rest = line.partition(": ")
    if not separator:
        return style_quoted_strings(runner, line)
    styled = f"{ansi_color(event_id, EVENT_ID_COLOR)}: {color_event_listing_commandlet(event, rest)}"
    return style_quoted_strings(runner, styled)


def style_quoted_strings(runner: Runner | None, text: str) -> str:
    """Apply `display/style.string` to single- or double-quoted spans."""
    if runner is None:
        return text
    style = runner.registry.varstore.get(DISPLAY_STRING_STYLE_VAR, "")
    if not style:
        return text
    parts: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char not in {"'", '"'}:
            parts.append(char)
            index += 1
            continue
        end = closing_quote_index(text, index)
        if end is None:
            parts.append(ansi_color(text[index:], style))
            break
        parts.append(ansi_color(text[index:end + 1], style))
        index = end + 1
    return "".join(parts)


def closing_quote_index(text: str, start: int) -> int | None:
    """Return the matching quote index, ignoring backslash-escaped quotes."""
    quote = text[start]
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index
        index += 1
    return None


def color_event_listing_commandlet(event, text: str) -> str:
    """Color commandlet names in compact event rows when they are identifiable."""
    commandlet = event.payload.get("commandlet") or event.payload.get("source")
    if not commandlet and event.source not in {"framework", "runner", "test"}:
        commandlet = event.source
    if not commandlet:
        return text
    commandlet_text = str(commandlet)
    colored = ansi_color(commandlet_text, EVENT_COMMANDLET_COLOR)
    if text.startswith(f"{commandlet_text} "):
        return f"{colored}{text[len(commandlet_text):]}"
    if text.startswith(f"{commandlet_text}:"):
        return f"{colored}{text[len(commandlet_text):]}"
    return text.replace(f"commandlet={commandlet_text}", f"commandlet={colored}", 1)
