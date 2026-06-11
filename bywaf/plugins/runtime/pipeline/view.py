"""Display helpers for the runtime pipeline commandlet."""

from __future__ import annotations

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.pipeline.detail import (
    format_pipeline,
    format_pipeline_artifacts,
    format_pipeline_inspection_hints,
    format_pipeline_jobs,
    format_pipeline_steps,
)
from bywaf.plugins.runtime.view import (
    apply_runtime_new_cursor,
    filter_runtime_rows_by_events,
    filter_runtime_rows_since,
    view_run_ids,
)
from bywaf.runtime_display import (
    command_context_style_getter,
    format_runtime_duration,
    format_runtime_timestamp,
    render_table,
    runtime_sort_note,
    runtime_sort_key,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    terminal_table_width,
)

PIPELINE_SORT_KEYS = ("id", "serial", "state", "job", "status", "steps", "events", "started")

__all__ = [
    "PIPELINE_SORT_KEYS",
    "filter_view_only_pipelines",
    "format_pipeline",
    "format_pipeline_artifacts",
    "format_pipeline_inspection_hints",
    "format_pipeline_jobs",
    "format_pipeline_steps",
    "print_pipelines",
    "sort_pipeline_rows",
]


def print_pipelines(
    context: CommandContext,
    *,
    active_only: bool = True,
    show_active: bool = False,
    page: bool = False,
    filters: dict[str, str] | None = None,
    highlight_newest: bool = False,
    since: str = "",
    sort_key: str = "",
) -> None:
    """Print active pipelines by default, or all pipelines when requested."""
    runtime = context.runtime_store("pipeline list")
    # Start from runtime rows, then apply visibility filtering, since/event
    # selectors, the per-command "new" cursor, and optional user sorting.
    rows = runtime.pipelines(active_only=active_only)
    rows = filter_view_only_pipelines(context, rows)
    rows = filter_runtime_rows_since(runtime, "pipeline", rows, since)
    if filters:
        events = context.event_store("pipeline list")
        rows = filter_runtime_rows_by_events(events, "pipeline", rows, filters)
    rows, newest_alias = apply_runtime_new_cursor(context, "pipeline", rows, highlight_newest)
    if sort_key:
        rows = sort_pipeline_rows(rows, sort_key)
    if not rows:
        if highlight_newest:
            context.output("no new pipelines")
        else:
            context.output("no matching pipelines" if filters or since else "no active pipelines" if active_only else "no pipelines")
        return
    names = runtime.runtime_names()
    aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_pipeline()
    table_rows: list[tuple[object, ...]] = []
    row_subjects: list[str] = []
    for row in rows:
        statuses = row["job_statuses"] or "unknown"
        state = runtime_state_label(statuses)
        table_rows.append(
            (
                aliases.get(str(row["pipeline_id"]), str(row["pipeline_id"])),
                runtime_status_summary(statuses),
                row["job_id"],
                row["runs"],
                row["events"],
                artifact_counts.get(str(row["pipeline_id"]), 0),
                format_runtime_timestamp(row["first_seen"]),
                format_runtime_duration(row["first_seen"], row["last_seen"]),
                names.get(("pipeline", str(row["pipeline_id"])), ""),
            )
        )
        row_subjects.append(
            "table.active_row"
            if state in {"active", "in progress"} or int(aliases.get(str(row["pipeline_id"]), "0")) == newest_alias
            else ""
        )
    output = render_table(
        ("PIPELINE", "STATUS", "JOB", "STEPS", "EVENTS", "ART", "STARTED", "DUR", "NAME"),
        table_rows,
        cell_subjects=("pipeline", "", "job", "", "", "", "timestamp", "timestamp", ""),
        row_subjects=row_subjects,
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    if sort_key:
        output = f"{runtime_sort_note(sort_key)}\n{output}"
    if since:
        output = f"after pipeline {since}\n{output}"
    if page:
        context.page_text(output)
    else:
        context.output(output)


def filter_view_only_pipelines(context: CommandContext, rows: list[dict]) -> list[dict]:
    """Return pipelines with at least one project-modifying step."""
    if not rows:
        return rows
    pipeline_ids = {str(row["pipeline_id"]) for row in rows}
    runs = [row for row in context.runtime_store("pipeline list runs").runs(active_only=False) if str(row["pipeline_id"]) in pipeline_ids]
    view_runs = view_run_ids(context.event_store("pipeline list runs"), runs)
    pipelines_with_runs = {str(row["pipeline_id"]) for row in runs}
    modifying_pipeline_ids = {
        str(row["pipeline_id"])
        for row in runs
        if str(row["command_run_id"]) not in view_runs
    }
    return [
        row
        for row in rows
        if str(row["pipeline_id"]) in modifying_pipeline_ids or str(row["pipeline_id"]) not in pipelines_with_runs
    ]


def sort_pipeline_rows(rows: list[dict], sort_key: str) -> list[dict]:
    """Return pipeline rows ordered by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    # Dispatch table for sort_pipeline_rows(): translates public sort keys into
    # concrete row values used by Python's stable sorter.
    sorters = {
        "id": lambda row: int(row["pipeline_id"]),
        "serial": lambda row: str(row["pipeline_id"]),
        "state": lambda row: runtime_state_label(row["job_statuses"] or "unknown"),
        "job": lambda row: int(row["job_id"] or 0),
        "status": lambda row: str(row["job_statuses"] or "unknown"),
        "steps": lambda row: int(row["runs"]),
        "events": lambda row: int(row["events"]),
        "started": lambda row: str(row["first_seen"] or ""),
    }
    return sorted(rows, key=sorters[display_key], reverse=runtime_sort_reverse(sort_key))
