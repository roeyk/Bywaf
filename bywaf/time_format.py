"""Timestamp formatting helpers for operator-facing output.

Provides one place for Bywaf's human-readable timestamp policy so REPL,
runtime, audit, and plugin commandlets do not duplicate date/time formatting.

Used by:
- REPL display: render event details and history.
- runtime display and runtime commandlets: render compact table timestamps.
- audit and note commandlets: render evidence rows consistently."""

from __future__ import annotations

from datetime import datetime


OPERATOR_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %Z"
COMPACT_RUNTIME_TIMESTAMP_FORMAT = "%H:%M:%S"


def format_operator_timestamp(value: datetime) -> str:
    """Return `YYYY-MM-DD HH:MM:SS TZ` in the operator's local timezone."""
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


def parse_iso_timestamp(value: str) -> datetime | None:
    """Parse an ISO timestamp string, accepting a trailing `Z` for UTC."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_history_timestamp_for_display(timestamp: str) -> str:
    """Normalize known history timestamp layouts to `YYYY-MM-DD HH:MM:SS TZ`."""
    parts = timestamp.split()
    if len(parts) == 3 and len(parts[0]) == 10 and ":" in parts[2]:
        # Older history entries stored date timezone time. New display prefers
        # date time timezone, but the file remains script-friendly either way.
        return f"{parts[0]} {parts[2]} {parts[1]}"
    return timestamp
