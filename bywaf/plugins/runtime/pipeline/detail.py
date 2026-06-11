"""Detail rendering helpers for the runtime pipeline commandlet.

Called by: `bywaf.plugins.runtime.pipeline.show_pipeline_action()` to compose
the `pipeline <id>` inspection view from summary, job, step, artifact, and
follow-up-command sections.
"""

from __future__ import annotations

from collections import Counter

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.artifact.summary import artifact_events_for_pipeline, render_artifact_summary
from bywaf.plugins.runtime.job import format_job_command
from bywaf.runtime_display import (
    command_context_style_getter,
    display_runtime_serial,
    format_runtime_duration,
    format_runtime_timestamp,
    render_table,
    runtime_state_label,
    runtime_status_summary,
    state_marker,
    terminal_table_width,
)
from bywaf.style import styled_subject_text

NOISE_TOPIC_PREFIXES = ("command.run.", "plugin.capability.", "plugin.progress.")
NOISE_TOPICS = {"framework.console.output.requested", "console.output", "runtime.name.assigned"}


def format_pipeline_artifacts(context: CommandContext, pipeline_id: str, shown_pipeline_id: str) -> str:
    """Render artifacts attached anywhere in one pipeline."""
    return render_artifact_summary(
        context,
        artifact_events_for_pipeline(context, pipeline_id),
        inspect_command=f"artifact list pipeline={shown_pipeline_id}",
    )


def format_pipeline_hints(context: CommandContext, pipeline_id: str) -> str:
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
