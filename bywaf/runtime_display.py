"""Runtime state formatting helpers.

Provides reusable labels, timestamps, active-state text, serial shortening, and
table rendering for jobs, runs, and pipelines.

Used by:
- REPL display and runtime commandlets: present runtime state consistently.
- tests: validate active/inactive listing formats."""


from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
from .command.parser import parse_pipeline
from .db.support import SERIAL_DISPLAY_LENGTH, serial_body
from .event.filters import parse_payload_filter_tokens
from .runtime_table_widths import (
    shrink_table_widths as shrink_table_widths,
    terminal_table_width as terminal_table_width,
    truncate_cell as truncate_cell,
)
from .runtime_tables import (
    StyleGetter,
    render_table as render_table,
    style_table_cell as style_table_cell,
    style_table_header as style_table_header,
)
from .time_format import format_compact_runtime_ts, format_duration_between

# Public runtime-display surface. The concrete table-width and table-rendering
# implementations live in narrower modules, but many runtime plugins import the
# names from here to keep their display code stable and easy to discover.
ACTIVE_LISTING_FORMAT_VAR = "listing.active-format"
DEFAULT_ACTIVE_LISTING_FORMAT = "short"
SORT_SELECTOR = "sort"
RUNTIME_FILTER_COMPLETIONS = (
    "host=",
    "port=",
    "protocol=",
    "service=",
    "state=",
    "status=",
    "source=",
    "topic=",
    "since=",
)


def normalize_active_listing_format(value: str | None) -> str:
    """Return a supported active-state display format.

    Called by: `active_listing_format()` when resolving REPL display settings.
    """
    if value in {"short", "long"}:
        return value
    return DEFAULT_ACTIVE_LISTING_FORMAT


def active_listing_format(getter) -> str:
    """Resolve the configured active-state display format.

    Called by: runtime list/detail renderers that need the operator's preferred
    short or long active-state text.
    """
    return normalize_active_listing_format(getter(ACTIVE_LISTING_FORMAT_VAR, DEFAULT_ACTIVE_LISTING_FORMAT))


ACTIVE_RUNTIME_STATUSES = {"running", "paused"}
IN_PROGRESS_RUNTIME_STATUSES = {"queued", "claimed", "pausing", "cancelling"}
FAILED_RUNTIME_STATUSES = {"failed", "missing", "stale"}
DISPLAY_SERIAL_PREFIXES = ("pipeline-", "run-", "job-")


def runtime_state_label(statuses: str | list[str] | tuple[str, ...] | None) -> str:
    """Collapse one or more runtime statuses into a listing label.

    Called by: job, step, pipeline, and result display helpers when a row may
    summarize one status or a group of child statuses.
    """
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
    """Normalize DB status strings into a tuple.

    Called by: runtime state label/summary helpers before applying display
    precedence rules.
    """
    if statuses is None:
        return ()
    if isinstance(statuses, str):
        return tuple(status.strip() for status in statuses.split(",") if status.strip())
    return tuple(str(status).strip() for status in statuses if str(status).strip())


def state_marker(label: str, timestamp: str | None, *, style: str) -> tuple[str, str]:
    """Return a row prefix and optional detail line for a runtime-state marker.

    Called by: REPL runtime display code that can show active state either as a
    compact prefix or as a longer companion detail line.
    """
    if style == "long":
        detail = f"  [{label} since {format_runtime_timestamp(timestamp)}]"
        return "", detail
    return f"[{label}] ", ""


def runtime_state_text(statuses: str | list[str] | tuple[str, ...] | None, timestamp: str | None, *, style: str) -> str:
    """Return the state cell text for runtime tables.

    Called by: table renderers that need a single lifecycle/status cell.
    """
    label = runtime_state_label(statuses)
    if style == "long":
        return f"{label} since {format_runtime_timestamp(timestamp)}"
    return label


def runtime_status_summary(statuses: str | list[str] | tuple[str, ...] | None) -> str:
    """Return one compact lifecycle cell combining state and raw status.

    Called by: runtime list renderers where users need both the derived state
    and the raw job status when they differ.
    """
    label = runtime_state_label(statuses)
    raw = "/".join(normalize_statuses(statuses)) or "unknown"
    return label if raw == label else f"{label}/{raw}"


def format_runtime_timestamp(value: str | None) -> str:
    """Render an ISO timestamp compactly for runtime listings.

    Called by: event, job, step, and pipeline display paths.
    """
    return format_compact_runtime_ts(value)


def format_runtime_duration(start: str | None, end: str | None) -> str:
    """Render a human duration for runtime listings.

    Called by: runtime list/detail renderers for elapsed-time cells.
    """
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

    Called by: runtime command selector parsers for job, results, port, and
    inventory-style views.
    """
    filters: list[str] = []
    sort_key = ""
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"{command} uses selector syntax; use sort=<key>, not {token}")
        key, separator, value = token.partition("=")
        if key == SORT_SELECTOR and separator:
            # Pull sort= out of the payload filters before delegating the
            # remaining field=value selectors to the shared event-filter parser.
            sort_key = parse_runtime_sort(value, allowed_sort_keys, command)
        else:
            filters.append(token)
    return parse_payload_filter_tokens(filters), sort_key


def parse_runtime_sort(raw: str, allowed_sort_keys: Sequence[str], command: str) -> str:
    """Validate a runtime-table sort key.

    Called by: selector parsers for runtime commands that support `sort=`.
    """
    sort_key = runtime_sort_key(raw)
    if sort_key in allowed_sort_keys:
        return raw
    choices = ", ".join(allowed_sort_keys)
    raise ValueError(f"{command} sort= must be one of: {choices}")


def runtime_sort_key(sort_key: str) -> str:
    """Return the field name portion of an optionally descending sort key.

    Called by: runtime sort validators and display-note helpers.
    """
    return sort_key[1:] if sort_key.startswith("-") else sort_key


def runtime_sort_reverse(sort_key: str) -> bool:
    """Return whether a sort key requests descending order.

    Called by: runtime table sorting and sort-note renderers.
    """
    return sort_key.startswith("-")


def runtime_sort_note(sort_key: str, *, label: str = "sorted by") -> str:
    """Return the operator-facing sort note for sorted runtime tables.

    Called by: runtime commandlets after applying non-default ordering.
    """
    key = runtime_sort_key(sort_key)
    if runtime_sort_reverse(sort_key):
        return f"{label} {key} descending (use sort={key} to sort ascending)"
    return f"{label} {key} ascending (use sort=-{key} to sort descending)"


def runtime_sort_candidates(prefix: str, allowed_sort_keys: Sequence[str]) -> list[str]:
    """Return ascending and descending `sort=` completion candidates.

    Called by: `runtime_view_candidates()` when the user is completing `sort=`.
    """
    candidates = [f"sort={key}" for key in allowed_sort_keys]
    candidates.extend(f"sort=-{key}" for key in allowed_sort_keys)
    return [candidate for candidate in candidates if candidate.startswith(prefix)]


def runtime_view_candidates(prefix: str, allowed_sort_keys: Sequence[str]) -> list[str]:
    """Return common runtime view selector completion candidates.

    Called by: runtime commandlet `complete()` methods for list/view selectors.
    """
    candidates = [*RUNTIME_FILTER_COMPLETIONS, "sort="]
    if prefix.startswith("sort="):
        candidates = runtime_sort_candidates(prefix, allowed_sort_keys)
    return [candidate for candidate in candidates if candidate.startswith(prefix)]


def display_runtime_serial(value: object | None) -> str:
    """Return a compact display value for durable runtime serials.

    Called by: runtime detail/list renderers that display persisted pipeline,
    run, or job serials.
    """
    if value is None:
        return ""
    text = str(value)
    for prefix in DISPLAY_SERIAL_PREFIXES:
        if text.startswith(prefix):
            return serial_body(text)[:SERIAL_DISPLAY_LENGTH]
    return text


def commandlet_from_command_line(command_line: str) -> str:
    """Return the first commandlet name in a stored command line.

    Called by: job filters and runtime display rows that need a commandlet
    label from the stored user command.
    """
    try:
        pipeline = parse_pipeline(command_line)
    except ValueError:
        return command_line.split(maxsplit=1)[0] if command_line.split() else ""
    if not pipeline.commands:
        return ""
    return pipeline.commands[0].name


def args_from_command_line(command_line: str) -> tuple[str, ...]:
    """Return plugin-owned arguments for the first commandlet in a stored line.

    Called by: runtime detail views that expose the arguments passed to the
    first commandlet in a pipeline.
    """
    try:
        pipeline = parse_pipeline(command_line)
    except ValueError:
        tokens = command_line.split()
        return tuple(tokens[1:]) if len(tokens) > 1 else ()
    if not pipeline.commands:
        return ()
    return tuple(pipeline.commands[0].args)


def format_command_args(args: Sequence[str]) -> str:
    """Return shell-style commandlet arguments for inspection output.

    Called by: runtime detail views after `args_from_command_line()`.
    """
    return " ".join(shlex.quote(arg) for arg in args)


def command_context_style_getter(context) -> StyleGetter:
    """Return a display-style getter for a commandlet context.

    Called by: runtime and plugin result renderers before invoking
    `render_table()`.
    """
    def get(key: str, default: str = "") -> object:
        # Per-run variables win over persisted display variables so one command
        # invocation can override styling without mutating global settings.
        run_vars = context.metadata.get("run_vars", {})
        if isinstance(run_vars, Mapping) and key in run_vars:
            return str(run_vars[key])
        display_vars = context.metadata.get("display_vars")
        if isinstance(display_vars, Mapping):
            return str(display_vars.get(key, default))
        return default

    return get
