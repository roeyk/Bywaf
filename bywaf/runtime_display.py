"""Runtime listing display helpers."""

from __future__ import annotations

from collections.abc import Sequence

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
    if not value:
        return "unknown"
    return value.replace("T", " ").replace("+00:00", " UTC")


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
