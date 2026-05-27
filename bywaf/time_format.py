"""Timestamp formatting helpers for operator-facing output.

Provides one place for Bywaf's human-readable timestamp policy so REPL,
runtime, audit, and plugin commandlets do not duplicate date/time formatting.

Used by:
- REPL display: render event details and history.
- runtime display and runtime commandlets: render compact table timestamps.
- audit and note commandlets: render evidence rows consistently."""

from __future__ import annotations

from datetime import datetime


OPERATOR_TIMESTAMP_FORMAT = "%Y%m%d %H:%M:%S %Z"
COMPACT_RUNTIME_TIMESTAMP_FORMAT = "%Y%m%d %H:%M:%S"


def format_operator_timestamp(value: datetime) -> str:
    """Return `YYYYMMDD HH:MM:SS TZ` in the operator's local timezone."""
    return value.astimezone().strftime(OPERATOR_TIMESTAMP_FORMAT)


def format_compact_runtime_timestamp(value: str | None) -> str:
    """Render an ISO timestamp compactly for runtime listings."""
    if not value:
        return "unknown"
    parsed = parse_iso_timestamp(value)
    if parsed is None:
        return value
    timezone = parsed.tzname()
    suffix = f" {timezone}" if timezone else ""
    return f"{parsed.strftime(COMPACT_RUNTIME_TIMESTAMP_FORMAT)}{suffix}"


def format_duration_between(start: str | None, end: str | None) -> str:
    """Return a compact human duration between two ISO timestamps."""
    parsed_start = parse_iso_timestamp(start) if start else None
    parsed_end = parse_iso_timestamp(end) if end else None
    if parsed_start is not None and parsed_end is None:
        return "ongoing"
    if parsed_start is None or parsed_end is None:
        return ""
    total_seconds = max(0, int((parsed_end - parsed_start).total_seconds()))
    if total_seconds < 60:
        return f"{total_seconds}s"
    minutes, seconds = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


def parse_iso_timestamp(value: str) -> datetime | None:
    """Parse an ISO timestamp string, accepting a trailing `Z` for UTC."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_history_timestamp_for_display(timestamp: str) -> str:
    """Normalize known history timestamp layouts to `YYYYMMDD HH:MM:SS TZ`."""
    parts = timestamp.split()
    if len(parts) == 3 and len(parts[0]) == 10 and ":" in parts[2]:
        # Older history entries stored date timezone time. New display prefers
        # date time timezone, but the file remains script-friendly either way.
        return f"{compact_date(parts[0])} {parts[2]} {parts[1]}"
    if len(parts) == 3 and len(parts[0]) == 10 and ":" in parts[1]:
        return f"{compact_date(parts[0])} {parts[1]} {parts[2]}"
    return timestamp


def compact_date(value: str) -> str:
    """Return YYYYMMDD for known dashed dates, otherwise preserve the value."""
    if len(value) == 10 and value[4] == "-" and value[7] == "-":
        return value.replace("-", "")
    return value
