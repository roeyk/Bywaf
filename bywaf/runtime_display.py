"""Runtime state formatting helpers.

Provides reusable labels, timestamps, active-state text, serial shortening, and
table rendering for jobs, runs, and pipelines.

Used by:
- REPL display and runtime commandlets: present runtime state consistently.
- tests: validate active/inactive listing formats."""


from __future__ import annotations

import shlex
import shutil
from collections.abc import Callable, Mapping, Sequence
from .command.parser import parse_pipeline
from .db.support import SERIAL_DISPLAY_LENGTH, serial_body
from .event_filters import parse_payload_filter_tokens
from .style import styled_subject_text, subject_style
from .time_format import format_compact_runtime_timestamp, format_duration_between

ACTIVE_LISTING_FORMAT_VAR = "listing.active-format"
DEFAULT_ACTIVE_LISTING_FORMAT = "short"
SORT_SELECTOR = "sort"


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
    # Pipelines can summarize several job statuses. Active/in-progress/failure
    # labels intentionally dominate completed so operators notice work in flight
    # or work needing attention.
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


def runtime_status_summary(statuses: str | list[str] | tuple[str, ...] | None) -> str:
    """Return one compact lifecycle cell combining state and raw status."""
    label = runtime_state_label(statuses)
    raw = "/".join(normalize_statuses(statuses)) or "unknown"
    return label if raw == label else f"{label}/{raw}"


def format_runtime_timestamp(value: str | None) -> str:
    """Render an ISO timestamp compactly for runtime listings."""
    return format_compact_runtime_timestamp(value)


def format_runtime_duration(start: str | None, end: str | None) -> str:
    """Render a human duration for runtime listings."""
    return format_duration_between(start, end)


def parse_runtime_list_selectors(
    tokens: Sequence[str],
    *,
    allowed_sort_keys: Sequence[str],
    command: str,
) -> tuple[dict[str, str], str]:
    """Split view-command selectors into event filters plus an optional sort.

    Runtime view commands accept payload filters such as `host=192.0.2.10` and
    now reserve `sort=` for table ordering.  Older `--sort=...`-style tokens are
    rejected here so typoed flags do not silently behave like payload filters.
    """
    filters: list[str] = []
    sort_key = ""
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"{command} uses selector syntax; use sort=<key>, not {token}")
        key, separator, value = token.partition("=")
        if key == SORT_SELECTOR and separator:
            sort_key = parse_runtime_sort(value, allowed_sort_keys, command)
        else:
            filters.append(token)
    return parse_payload_filter_tokens(filters), sort_key


def parse_runtime_sort(raw: str, allowed_sort_keys: Sequence[str], command: str) -> str:
    """Validate a runtime-table sort key."""
    if raw in allowed_sort_keys:
        return raw
    choices = ", ".join(allowed_sort_keys)
    raise ValueError(f"{command} sort= must be one of: {choices}")


def runtime_sort_note(sort_key: str) -> str:
    """Return the operator-facing sort note for sorted runtime tables."""
    return f"sorted by {sort_key} ascending"


def display_runtime_serial(value: object | None) -> str:
    """Return a compact display value for durable runtime serials."""
    if value is None:
        return ""
    text = str(value)
    for prefix in DISPLAY_SERIAL_PREFIXES:
        if text.startswith(prefix):
            return serial_body(text)[:SERIAL_DISPLAY_LENGTH]
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


def args_from_command_line(command_line: str) -> tuple[str, ...]:
    """Return plugin-owned arguments for the first commandlet in a stored line."""
    try:
        pipeline = parse_pipeline(command_line)
    except ValueError:
        tokens = command_line.split()
        return tuple(tokens[1:]) if len(tokens) > 1 else ()
    if not pipeline.commands:
        return ()
    return tuple(pipeline.commands[0].args)


def format_command_args(args: Sequence[str]) -> str:
    """Return shell-style commandlet arguments for inspection output."""
    return " ".join(shlex.quote(arg) for arg in args)


StyleGetter = Callable[[str, str], object]


def command_context_style_getter(context) -> StyleGetter:
    """Return a display-style getter for a commandlet context."""
    def get(key: str, default: str = "") -> object:
        run_vars = context.metadata.get("run_vars", {})
        if isinstance(run_vars, Mapping) and key in run_vars:
            return str(run_vars[key])
        display_vars = context.metadata.get("display_vars")
        if isinstance(display_vars, Mapping):
            return str(display_vars.get(key, default))
        return default

    return get


def render_table(
    headers: tuple[str, ...],
    rows: Sequence[Sequence[object]],
    *,
    cell_subjects: Sequence[str] = (),
    row_subjects: Sequence[str] = (),
    active_column_indexes: Sequence[int] = (),
    style_getter: StyleGetter | None = None,
    max_width: int | None = None,
) -> str:
    """Render a small table, optionally styling aligned cells by subject."""
    if not rows:
        return ""
    text_rows = [[str(value) if value is not None else "" for value in row] for row in rows]
    widths = [
        max(len(header), *(len(row[index]) for row in text_rows))
        for index, header in enumerate(headers)
    ]
    if max_width is not None:
        widths = shrink_table_widths(widths, headers, max_width)
        text_rows = [[truncate_cell(value, widths[index]) for index, value in enumerate(row)] for row in text_rows]
    lines = [
        "  ".join(
            style_table_header(
                truncate_cell(header, widths[index]).ljust(widths[index]),
                style_getter,
            )
            for index, header in enumerate(headers)
        ),
        "  ".join(style_table_header("-" * width, style_getter) for width in widths),
    ]
    lines.extend(
        "  ".join(
            style_table_cell(
                value.ljust(widths[index]),
                cell_subjects[index] if index < len(cell_subjects) else "",
                style_getter,
                column_index=index,
                row_subject=row_subject,
                active_column=bool(row_subject) and index in active_column_indexes,
            )
            for index, value in enumerate(row)
        )
        for row_index, row in enumerate(text_rows)
        for row_subject in (row_subjects[row_index] if row_index < len(row_subjects) else "",)
    )
    return "\n".join(lines)


def terminal_table_width(fallback: int = 100) -> int:
    """Return the current terminal width for view-command tables."""
    return shutil.get_terminal_size(fallback=(fallback, 24)).columns


def shrink_table_widths(widths: list[int], headers: Sequence[str], max_width: int) -> list[int]:
    """Shrink wide columns until a table fits the requested display width."""
    if not widths:
        return widths
    available = max(1, max_width - (2 * (len(widths) - 1)))
    minimums = [min(max(len(header), 3), width) for header, width in zip(headers, widths)]
    if available < sum(minimums):
        compressed = [1] * len(widths)
        remaining = max(0, available - len(compressed))
        for index in sorted(range(len(widths)), key=lambda item: widths[item], reverse=True):
            if remaining <= 0:
                break
            room = max(0, min(widths[index], minimums[index]) - compressed[index])
            growth = min(room, remaining)
            compressed[index] += growth
            remaining -= growth
        return compressed
    shrunk = list(widths)
    while sum(shrunk) > available:
        candidates = [index for index, width in enumerate(shrunk) if width > minimums[index]]
        if not candidates:
            break
        index = max(candidates, key=lambda candidate: shrunk[candidate] - minimums[candidate])
        shrunk[index] -= 1
    return shrunk


def truncate_cell(value: str, width: int) -> str:
    """Trim one table cell to width, preserving a visible ellipsis."""
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "…"


def style_table_header(value: str, style_getter: StyleGetter | None) -> str:
    """Apply the configured table-heading style to one header/ruler cell."""
    if style_getter is None or not value.strip():
        return value
    return styled_subject_text(style_getter, "table.header", value)


def style_table_cell(
    value: str,
    subject: str,
    style_getter: StyleGetter | None,
    *,
    column_index: int,
    row_subject: str = "",
    active_column: bool = False,
) -> str:
    """Apply a subject style to a padded table cell when configured."""
    if style_getter is None or not value.strip():
        return value
    cell_subject = table_cell_subject(
        subject,
        style_getter,
        column_index=column_index,
        row_subject=row_subject,
        active_column=active_column,
    )
    return styled_subject_text(style_getter, cell_subject, value) if cell_subject else value


def table_cell_subject(
    subject: str,
    style_getter: StyleGetter,
    *,
    column_index: int,
    row_subject: str = "",
    active_column: bool = False,
) -> str:
    """Return the most specific configured style subject for a table cell."""
    if active_column and subject_style(style_getter, "table.active_column"):
        return "table.active_column"
    if row_subject and subject_style(style_getter, row_subject):
        return row_subject
    if subject and subject_style(style_getter, subject):
        return subject
    if column_index == 0 and subject_style(style_getter, "table.index"):
        return "table.index"
    if subject_style(style_getter, "table.body"):
        return "table.body"
    return subject
