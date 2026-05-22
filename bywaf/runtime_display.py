"""Runtime state formatting helpers.

Provides reusable labels, timestamps, active-state text, serial shortening, and
table rendering for jobs, runs, and pipelines.

Used by:
- REPL display and runtime commandlets: present runtime state consistently.
- tests: validate active/inactive listing formats."""


from __future__ import annotations

from collections.abc import Sequence
from .command_parser import parse_pipeline
from .time_format import format_compact_runtime_timestamp

ACTIVE_LISTING_FORMAT_VAR = "listing.active-format"
DEFAULT_ACTIVE_LISTING_FORMAT = "short"


def normalize_active_listing_format(value: str | None) -> str:
    """Return a supported active-state display format."""
    if value in {"short", "long"}:
        return value
    return DEFAULT_ACTIVE_LISTING_FORMAT


def active_listing_format(getter) -> str:
    """Resolve the configured active-state display format."""
    return normalize_active_listing_format(getter(ACTIVE_LISTING_FORMAT_VAR, DEFAULT_ACTIVE_LISTING_FORMAT))


ACTIVE_RUNTIME_STATUSES = {"running", "paused"}
IN_PROGRESS_RUNTIME_STATUSES = {"queued", "claimed", "pausing", "cancelling"}
FAILED_RUNTIME_STATUSES = {"failed", "missing", "stale"}
DISPLAY_SERIAL_PREFIXES = ("pipeline-", "run-", "job-")


def runtime_state_label(statuses: str | list[str] | tuple[str, ...] | None) -> str:
    """Collapse one or more runtime statuses into a listing label."""
    values = normalize_statuses(statuses)
    if any(status in ACTIVE_RUNTIME_STATUSES for status in values):
        return "active"
    if any(status in IN_PROGRESS_RUNTIME_STATUSES for status in values):
        return "in progress"
    if any(status in FAILED_RUNTIME_STATUSES for status in values):
        return "failed"
    return "completed"


def normalize_statuses(statuses: str | list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    """Normalize DB status strings into a tuple."""
    if statuses is None:
        return ()
    if isinstance(statuses, str):
        return tuple(status.strip() for status in statuses.split(",") if status.strip())
    return tuple(str(status).strip() for status in statuses if str(status).strip())


def state_marker(label: str, timestamp: str | None, *, style: str) -> tuple[str, str]:
    """Return a row prefix and optional detail line for a runtime-state marker."""
    if style == "long":
        detail = f"  [{label} since {format_runtime_timestamp(timestamp)}]"
        return "", detail
    return f"[{label}] ", ""


def runtime_state_text(statuses: str | list[str] | tuple[str, ...] | None, timestamp: str | None, *, style: str) -> str:
    """Return the state cell text for runtime tables."""
    label = runtime_state_label(statuses)
    if style == "long":
        return f"{label} since {format_runtime_timestamp(timestamp)}"
    return label


def format_runtime_timestamp(value: str | None) -> str:
    """Render an ISO timestamp compactly for runtime listings."""
    return format_compact_runtime_timestamp(value)


def display_runtime_serial(value: object | None) -> str:
    """Return a compact display value for durable runtime serials."""
    if value is None:
        return ""
    text = str(value)
    for prefix in DISPLAY_SERIAL_PREFIXES:
        if text.startswith(prefix):
            return text.removeprefix(prefix)
    return text


def commandlet_from_command_line(command_line: str) -> str:
    """Return the first commandlet name in a stored command line."""
    try:
        pipeline = parse_pipeline(command_line)
    except ValueError:
        return command_line.split(maxsplit=1)[0] if command_line.split() else ""
    if not pipeline.commands:
        return ""
    return pipeline.commands[0].name


def render_table(headers: tuple[str, ...], rows: Sequence[Sequence[object]]) -> str:
    """Render a small plain-text table with padded columns."""
    if not rows:
        return ""
    text_rows = [[str(value) if value is not None else "" for value in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in text_rows))
        for index, header in enumerate(headers)
    ]
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in text_rows
    )
    return "\n".join(lines)
