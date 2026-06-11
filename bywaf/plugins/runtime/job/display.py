"""Job list/detail rendering helpers for the runtime `job` command."""

from __future__ import annotations

from bywaf.plugin import CommandContext, CompletionContext
from bywaf.plugins.runtime.job.filters import filter_job_rows
from bywaf.plugins.runtime.view import (
    apply_runtime_new_cursor,
    filter_rows_by_events,
    filter_runtime_rows_since,
    filter_view_job_rows,
)
from bywaf.runtime_display import (
    args_from_command_line,
    command_context_style_getter,
    commandlet_from_command_line,
    display_runtime_serial,
    format_command_args,
    format_runtime_duration,
    format_runtime_timestamp,
    render_table,
    runtime_sort_key,
    runtime_sort_note,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    state_marker,
    terminal_table_width,
)
from bywaf.style import styled_subject_text


def print_jobs(
    context: CommandContext,
    *,
    active_only: bool = True,
    show_active: bool = False,
    page: bool = False,
    filters: dict[str, str] | None = None,
    row_filters: dict[str, str] | None = None,
    highlight_newest: bool = False,
    since: str = "",
    sort_key: str = "",
) -> None:
    """Print known jobs with newest first.

    Called by: `list_job_action()` for the `job` command.
    """
    del show_active
    runtime = context.runtime_store("job list")
    # Start from durable runtime rows, then apply display-level visibility,
    # row selectors, event-payload selectors, and the per-command "new" cursor.
    rows = runtime.jobs(active_only=active_only)
    rows = filter_view_job_rows(context.event_store("job list"), rows)
    if row_filters:
        rows = filter_job_rows(rows, row_filters)
    rows = filter_runtime_rows_since(runtime, "job", rows, since)
    if filters:
        events = context.event_store("job list")
        rows = filter_rows_by_events(events, "job", rows, filters)
    rows, newest_id = apply_runtime_new_cursor(context, "job", rows, highlight_newest)
    if sort_key:
        rows = sort_job_rows(rows, sort_key)
    if not rows:
        if highlight_newest:
            context.output("no new jobs")
        else:
            context.output("no matching jobs" if filters or row_filters or since else "no active jobs" if active_only else "no jobs")
        return
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
    table_rows: list[tuple[object, ...]] = []
    row_subjects: list[str] = []
    for row in rows:
        # Listings keep time in STARTED/DUR only. Detail views can carry richer
        # lifecycle prose without duplicating timestamps across table cells.
        state = runtime_state_label(row["status"])
        table_rows.append(
            (
                row["id"],
                runtime_status_summary(row["status"]),
                format_runtime_timestamp(row["started_at"]),
                format_runtime_duration(row["started_at"], row["finished_at"]),
                artifact_counts.get(str(row["id"]), 0),
                names.get(("job", str(row["id"])), ""),
                format_job_command(str(row["command_line"])),
            )
        )
        row_subjects.append("table.active_row" if state in {"active", "in progress"} or int(row["id"]) == newest_id else "")
    output = render_table(
        ("JOB", "STATUS", "STARTED", "DUR", "ART", "NAME", "COMMAND"),
        table_rows,
        cell_subjects=("job", "", "timestamp", "timestamp", "", "", "command_line"),
        row_subjects=row_subjects,
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    if sort_key:
        output = f"{runtime_sort_note(sort_key)}\n{output}"
    if since:
        output = f"after job {since}\n{output}"
    if page:
        context.page_text(output)
    else:
        context.output(output)


def sort_job_rows(rows: list[dict], sort_key: str) -> list[dict]:
    """Return job rows ordered by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    # Dispatch table for sort_job_rows(): translates the public sort key into
    # the row value used by Python's stable sorter.
    sorters = {
        "id": lambda row: int(row["id"]),
        "serial": lambda row: str(row["serial"]),
        "state": lambda row: runtime_state_label(row["status"]),
        "status": lambda row: str(row["status"]),
        "started": lambda row: str(row["started_at"] or ""),
        "commandlet": lambda row: commandlet_from_command_line(str(row["command_line"])),
    }
    return sorted(rows, key=sorters[display_key], reverse=runtime_sort_reverse(sort_key))


def format_job_command(command_line: str) -> str:
    """Return commandlet plus arguments as one compact table cell.

    Called by: `print_jobs()` and pipeline job-list renderers.
    """
    commandlet = commandlet_from_command_line(command_line)
    args = format_command_args(args_from_command_line(command_line))
    return f"{commandlet} {args}".strip()


def format_job(
    row,
    *,
    display_name: str | None = None,
    show_active: bool = False,
    marker_style: str = "short",
    args: list[str] | None = None,
    style_getter=None,
) -> str:
    """Format one job as a readable detail block.

    Called by: `show_job_action()`.
    """
    prefix = ""
    detail = ""
    if show_active:
        label = runtime_state_label(row["status"])
        timestamp = row["started_at"] if label in {"active", "in progress"} else row["finished_at"]
        prefix, detail = state_marker(label, timestamp, style=marker_style)
    job_id = styled_subject_text(style_getter, "job", row["id"]) if style_getter else row["id"]
    serial = display_runtime_serial(row["serial"])
    serial = styled_subject_text(style_getter, "serial", serial) if style_getter else serial
    command = str(row["command_line"])
    commandlet = commandlet_from_command_line(command)
    displayed_args = args or list(args_from_command_line(command))
    displayed_command = f"{commandlet} {format_command_args(displayed_args)}".strip() if displayed_args else command
    displayed_command = styled_subject_text(style_getter, "command_line", displayed_command) if style_getter else displayed_command
    lines = [
        f"  job: {prefix}{job_id}",
        f"  serial: {serial}",
        f"  pid: {row['pid']}",
        f"  status: {row['status']}",
        f"  launched: {format_runtime_timestamp(row['started_at'])}",
        f"  finished: {format_runtime_timestamp(row['finished_at'])}",
        f"  duration: {format_runtime_duration(row['started_at'], row['finished_at'])}",
        f"  command line: {displayed_command}",
    ]
    if display_name:
        lines.insert(3, f"  name: {display_name}")
    block = "Job summary\n" + "\n".join(lines)
    return f"{block}\n\n{detail}" if detail else block


def latest_job_args(context: CommandContext, job_id: int | str) -> list[str]:
    """Return the newest recorded commandlet arguments for a job, if present.

    Called by: `show_job_action()` to reconstruct redacted/quoted command
    display from structured argument events.
    """
    argument_events = context.event_store("job show arguments").events_for_job_topic(
        int(job_id),
        "command.run.arguments",
        limit=10000,
    )
    if not argument_events:
        return []
    payload_args = max(argument_events, key=lambda event: event.id or 0).payload.get("args")
    if isinstance(payload_args, list):
        return [str(arg) for arg in payload_args]
    return []


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion.

    Called by: runtime completion providers for job-like selectors.
    """
    try:
        runtime = context.runtime_store("job completion")
    except ValueError:
        return []
    return [str(row["id"]) for row in runtime.jobs()]
