"""Display helpers for the runtime pipeline commandlet."""

from __future__ import annotations

from collections import Counter

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.artifact.summary import artifact_events_for_pipeline, render_artifact_summary
from bywaf.plugins.runtime.job import format_job_command
from bywaf.plugins.runtime.view_common import (
    apply_runtime_new_cursor,
    filter_runtime_rows_by_events,
    filter_runtime_rows_since,
    view_run_ids,
)
from bywaf.runtime_display import (
    command_context_style_getter,
    display_runtime_serial,
    format_runtime_duration,
    format_runtime_timestamp,
    render_table,
    runtime_sort_note,
    runtime_sort_key,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    state_marker,
    terminal_table_width,
)
from bywaf.style import styled_subject_text

PIPELINE_SORT_KEYS = ("id", "serial", "state", "job", "status", "steps", "events", "started")
NOISE_TOPIC_PREFIXES = ("command.run.", "plugin.capability.", "plugin.progress.")
NOISE_TOPICS = {"framework.console.output.requested", "console.output", "runtime.name.assigned"}

def format_pipeline_artifacts(context: CommandContext, pipeline_id: str, shown_pipeline_id: str) -> str:
    """Render artifacts attached anywhere in one pipeline."""
    return render_artifact_summary(
        context,
        artifact_events_for_pipeline(context, pipeline_id),
        inspect_command=f"artifact list pipeline={shown_pipeline_id}",
    )


def format_pipeline_inspection_hints(context: CommandContext, pipeline_id: str) -> str:
    """Show the follow-up commands that inspect this pipeline's linked work."""
    runtime = context.runtime_store("pipeline show inspect")
    jobs = runtime.jobs_for_pipeline(pipeline_id)
    runs = [row for row in runtime.runs(active_only=False) if str(row["pipeline_id"]) == pipeline_id]
    run_aliases = runtime.run_aliases()
    commands: list[str] = []
    commands.extend(f"job {row['id']}" for row in jobs)
    for row in sorted(runs, key=lambda run: str(run["first_event"] or "")):
        step_id = run_aliases.get(str(row["command_run_id"]), str(row["command_run_id"]))
        commands.append(f"step {step_id}")
        commands.append(f"event step={step_id}")
        commands.append(f"event follow step={step_id}")
        commands.append(f"artifact list step={step_id}")
    return "Inspect: " + "; ".join(commands) if commands else ""


def format_pipeline_jobs(context: CommandContext, pipeline_id: str) -> str:
    """Render jobs attached to a pipeline for `pipeline <id>` detail output."""
    runtime = context.runtime_store("pipeline show jobs")
    rows = runtime.jobs_for_pipeline(pipeline_id)
    if not rows:
        return "Jobs: none"
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
    table_rows = [
        (
            row["id"],
            runtime_status_summary(row["status"]),
            format_runtime_timestamp(row["started_at"]),
            format_runtime_duration(row["started_at"], row["finished_at"]),
            artifact_counts.get(str(row["id"]), 0),
            names.get(("job", str(row["id"])), ""),
            format_job_command(str(row["command_line"])),
        )
        for row in rows
    ]
    return "Jobs\n" + render_table(
        ("JOB", "STATUS", "STARTED", "DUR", "ART", "NAME", "COMMAND"),
        table_rows,
        cell_subjects=("job", "", "timestamp", "timestamp", "", "", "command_line"),
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def format_pipeline_steps(context: CommandContext, pipeline_id: str) -> str:
    """Render steps attached to a pipeline for `pipeline <id>` detail output."""
    runtime = context.runtime_store("pipeline show steps")
    rows = [row for row in runtime.runs(active_only=False) if str(row["pipeline_id"]) == pipeline_id]
    if not rows:
        return "Steps: none"
    rows = sorted(rows, key=lambda row: str(row["first_event"] or ""))
    names = runtime.runtime_names()
    run_aliases = runtime.run_aliases()
    artifact_counts = runtime.artifact_counts_by_run()
    table_rows = [
        (
            run_aliases.get(str(row["command_run_id"]), row["command_run_id"]),
            runtime_status_summary(row["job_statuses"]),
            row["source"],
            format_step_inserted_topics(context, str(row["command_run_id"])),
            artifact_counts.get(str(row["command_run_id"]), 0),
            format_runtime_timestamp(row["first_event"]),
            format_runtime_duration(row["first_event"], row["last_event"]),
            names.get(("run", str(row["command_run_id"])), ""),
        )
        for row in rows
    ]
    return "Steps\n" + render_table(
        ("STEP", "STATUS", "COMMANDLET", "INSERTED", "ART", "STARTED", "DUR", "NAME"),
        table_rows,
        cell_subjects=("step", "", "", "", "", "timestamp", "timestamp", ""),
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def format_step_inserted_topics(context: CommandContext, command_run_id: str) -> str:
    """Summarize non-lifecycle event topics inserted by one step."""
    events = context.event_store("pipeline show inserted").events_matching(command_run_id=command_run_id, limit=100000)
    counts = Counter(event.topic for event in events if not is_noise_topic(event.topic))
    if not counts:
        counts = Counter(event.topic for event in events)
    return ", ".join(f"{topic}={count}" for topic, count in sorted(counts.items())) or "-"


def is_noise_topic(topic: str) -> bool:
    """Return whether a topic is lifecycle/audit noise for pipeline detail."""
    return topic in NOISE_TOPICS or topic.startswith(NOISE_TOPIC_PREFIXES)

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

def format_pipeline(
    row,
    *,
    display_name: str | None = None,
    alias: str | None = None,
    show_active: bool = False,
    marker_style: str = "short",
    style_getter=None,
) -> str:
    """Format one pipeline as a readable detail block."""
    statuses = row["job_statuses"] or "unknown"
    prefix = ""
    detail = ""
    if show_active:
        label = runtime_state_label(statuses)
        timestamp = row["first_seen"] if label in {"active", "in progress"} else row["last_seen"]
        prefix, detail = state_marker(label, timestamp, style=marker_style)
    pipeline_id = alias or row["pipeline_id"]
    pipeline_id = styled_subject_text(style_getter, "pipeline", pipeline_id) if style_getter else pipeline_id
    serial = display_runtime_serial(row["pipeline_id"])
    serial = styled_subject_text(style_getter, "serial", serial) if style_getter else serial
    lines = [
        f"  pipeline: {prefix}{pipeline_id}",
        f"  serial: {serial}",
        f"  job: {row['job_id']}",
        f"  status: {statuses}",
        f"  steps: {row['runs']}",
        f"  events: {row['events']}",
    ]
    if display_name:
        lines.insert(2, f"  name: {display_name}")
    block = "Pipeline summary\n" + "\n".join(lines)
    return f"{block}\n\n{detail}" if detail else block
