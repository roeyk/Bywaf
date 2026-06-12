"""Detail rendering for the runtime step commandlet.

Called by: `bywaf.plugins.runtime.step.Step.run()` when an operator inspects one
pipeline step with `step <id>`.
"""

from __future__ import annotations

from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.artifact.summary import artifact_events_for_step, render_artifact_summary
from bywaf.runtime_display import (
    command_context_style_getter,
    format_runtime_duration,
    format_runtime_timestamp,
    runtime_status_summary,
)
from bywaf.style import styled_subject_text


def show_step(context: CommandContext, step_id: str) -> None:
    """Print a compact inspection view for one pipeline step.

    Called by: `Step.run()` after `parse_step_operation()` identifies a detail
    request instead of a list/filter request.
    """
    runtime = context.runtime_store("step")
    run_id = runtime.resolve_run_serial(step_id)
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    style_getter = command_context_style_getter(context)
    sections: list[str] = []
    run_row = next((row for row in runtime.runs(active_only=False) if str(row["command_run_id"]) == run_id), None)
    if run_row is not None:
        # The first section is a stable summary of the selected command run.
        # Human-friendly aliases are shown beside serial IDs so users can move
        # between `step`, `event`, `artifact`, `pipeline`, and `job` commands.
        pipeline_serial = str(run_row["pipeline_id"]) if run_row["pipeline_id"] is not None else ""
        shown_step = styled_subject_text(style_getter, "step", run_aliases.get(run_id, run_id))
        shown_serial = styled_subject_text(style_getter, "serial", run_id)
        shown_pipeline = (
            styled_subject_text(style_getter, "pipeline", pipeline_aliases.get(pipeline_serial, pipeline_serial))
            if pipeline_serial
            else ""
        )
        sections.append(
            step_heading(style_getter, "Step summary")
            + "\n"
            + "\n".join(
                f"  {step_label(style_getter, label)}: {value}"
                for label, value in (
                    ("step", shown_step),
                    ("serial", shown_serial),
                    ("status", runtime_status_summary(run_row["job_statuses"])),
                    ("pipeline", shown_pipeline),
                    ("source", run_row["source"]),
                    ("events", run_row["events"]),
                    ("started", styled_subject_text(style_getter, "timestamp", format_runtime_timestamp(run_row["first_event"]))),
                    ("duration", styled_subject_text(style_getter, "timestamp", format_runtime_duration(run_row["first_event"], run_row["last_event"]))),
                )
                if value
            )
        )
    rows = runtime.command_run_var_rows(run_id)
    job_id = step_job_id(rows)
    relevant_rows = [row for row in rows if should_show_step_variable(str(row["name"]))]
    if relevant_rows:
        # Variables are runtime provenance, but display/style preferences are
        # filtered out below so the detail view emphasizes operator input and
        # commandlet configuration.
        sections.append(
            step_heading(style_getter, "Variables")
            + "\n"
            + "\n".join(
                f"  {styled_subject_text(style_getter, 'variable', row['name'])}={styled_subject_text(style_getter, 'value', row['value'])}"
                for row in relevant_rows[:25]
            )
        )
    elif rows:
        sections.append(
            step_heading(style_getter, "Variables")
            + "\n"
            + f"  {styled_subject_text(style_getter, 'comment', f'{len(rows)} captured runtime preferences hidden')}"
        )
    artifacts = artifact_events_for_step(context, run_id)
    if artifacts:
        # Artifact rendering is delegated to the artifact subsystem so the step
        # view stays consistent with `artifact list step=...`.
        sections.append(
            render_artifact_summary(
                context,
                artifacts,
                inspect_command=f"artifact list step={run_aliases.get(run_id, run_id)}",
            )
        )
    events = context.event_store("step").events_matching(command_run_id=run_id)
    if events:
        # Event rows are compact local summaries, not the full `event` command
        # output. The next-actions section points to richer follow-up commands.
        sections.append(
            step_heading(style_getter, "Events") + "\n" + "\n".join(f"  {format_step_event(event, style_getter=style_getter)}" for event in events)
        )
    sections.append(step_next_actions(run_aliases.get(run_id, run_id), job_id, events, style_getter=style_getter))
    context.output("\n\n".join(sections))


def step_heading(style_getter, text: str) -> str:
    """Style a step-detail section heading."""
    return styled_subject_text(style_getter, "report.section", text) if style_getter else text


def step_label(style_getter, text: str) -> str:
    """Style a step-detail label."""
    return styled_subject_text(style_getter, "report.label", text) if style_getter else text


def step_command(style_getter, text: str) -> str:
    """Style an inspect command."""
    return styled_subject_text(style_getter, "command_line", text) if style_getter else text


def step_job_id(rows: list[Any]) -> str:
    """Return the owning job id from run-variable rows when available."""
    for row in rows:
        value = row["job_id"]
        if value is not None:
            return str(value)
    return ""


def step_next_actions(step_id: str, job_id: str, events: list[Event], *, style_getter=None) -> str:
    """Return concise next commands for investigating one step."""
    commands = [f"event step={step_id}", f"event follow step={step_id}", f"artifact list step={step_id}"]
    if job_id:
        commands.insert(0, f"job {job_id}")
    text = f"{step_label(style_getter, 'inspect further with')}: " + "; ".join(step_command(style_getter, command) for command in commands)
    topics = {event.topic for event in events}
    # A missing terminal command.run event usually means a job died, was
    # interrupted, or predated lifecycle recording. Point the user at the job
    # view because it carries process status and errors.
    if job_id and "command.run.completed" not in topics and "command.run.failed" not in topics:
        text += f"\nNo step completion event was recorded; inspect owning job with `job {job_id}`."
    return text


def should_show_step_variable(name: str) -> bool:
    """Return whether a captured runtime variable is useful in step detail."""
    # Display preferences are useful for reproducing a session but distract
    # from scan inputs in step detail.
    return not (name.startswith("display.") or name.startswith("display/") or name.startswith("display/style."))


def format_step_event(event: Event, *, style_getter=None) -> str:
    """Render one step event line without relying on REPL internals."""
    event_id = styled_subject_text(style_getter, "table.index", event.id)
    topic = styled_subject_text(style_getter, "value", event.topic)
    return f"{event_id}: {topic} {format_step_payload(event.payload, style_getter=style_getter)}".rstrip()


def format_step_payload(payload: object, *, style_getter=None) -> str:
    """Render event payload values compactly for step inspection."""
    if not isinstance(payload, dict):
        return str(payload)
    if "text" in payload:
        # Console-output events can contain tables or long tool output; show
        # only a first-line preview here and leave full inspection to `event`.
        source = payload.get("source", "")
        return f"{step_label(style_getter, 'source')}={source} {step_label(style_getter, 'text')}={summarize_step_text(str(payload.get('text', '')))}".strip()
    if "host" in payload:
        # Host/port facts are high-volume and are easier to scan as endpoint
        # strings than as generic key=value payloads.
        parts = [str(payload.get("host", ""))]
        if payload.get("port") is not None:
            parts[-1] = f"{parts[-1]}:{payload['port']}"
        return " ".join(part for part in parts if part)
    return " ".join(f"{step_label(style_getter, str(key))}={styled_subject_text(style_getter, 'value', value)}" for key, value in payload.items())


def summarize_step_text(text: str, *, limit: int = 120) -> str:
    """Return the first useful line of captured console text."""
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if len(first_line) <= limit:
        return first_line
    return first_line[: limit - 1].rstrip() + "..."
