"""Runtime step commandlet.

Provides a bundled plugin implementation for listing and inspecting pipeline
steps. Steps are reconstructed from event and variable-snapshot records rather
than stored as mutable runtime rows.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: inspect commandlet execution steps through normal dispatch."""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.view_common import filter_runtime_rows_by_events, view_selector_candidates
from bywaf.runtime_display import (
    command_context_style_getter,
    format_runtime_duration,
    format_runtime_timestamp,
    parse_runtime_list_selectors,
    render_table,
    runtime_sort_note,
    runtime_sort_key,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    terminal_table_width,
)
from bywaf.style import styled_subject_text

STEP_SORT_KEYS = ("id", "serial", "state", "pipeline", "source", "events", "started")


@commandlet(
    name="step",
    description="List and inspect pipeline steps.",
    usage="step [--all] [field=value ...] | step <id>",
    examples=("step", "step --all", "step 1", "step host=192.0.2.10"),
    capabilities=("framework.console.output",),
    database_actions=("view",),
)
class Step(CommandletBase):
    """List and inspect commandlet execution steps."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one step inspection operation."""
        del input_events
        parser = self.parser()
        parser.add_argument("--all", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        operation = parse_step_operation(tokens)
        context.require_foreground("step inspection commands")
        if operation.id:
            show_step(context, operation.id)
        else:
            print_steps(
                context,
                active_only=False,
                filters=operation.filters,
                sort_key=operation.sort,
            )
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete step IDs and list options from the active database."""
        candidates = ["--all", "sort=", *step_ids(context)]
        if not args:
            return candidates
        if args and args[-1].startswith("sort="):
            return view_selector_candidates(args[-1], STEP_SORT_KEYS)
        candidates.extend(view_selector_candidates(prefix, STEP_SORT_KEYS))
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_step_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `step` forms into an optional id plus filters."""
    if not tokens:
        return Namespace(id=None, filters={}, sort="")
    if len(tokens) == 1 and "=" not in tokens[0]:
        return Namespace(id=tokens[0], filters={}, sort="")
    filters, sort = parse_runtime_list_selectors(tokens, allowed_sort_keys=STEP_SORT_KEYS, command="step")
    return Namespace(id=None, filters=filters, sort=sort)


def print_steps(
    context: CommandContext,
    *,
    active_only: bool = True,
    filters: dict[str, str] | None = None,
    sort_key: str = "",
) -> None:
    """Print commandlet step summaries."""
    runtime = context.runtime_store("step")
    rows = runtime.runs(active_only=active_only)
    if filters:
        events = context.event_store("step")
        rows = filter_runtime_rows_by_events(events, "step", rows, filters)
    if sort_key:
        rows = sort_step_rows(rows, sort_key)
    if not rows:
        context.output("no matching steps" if filters else "no active steps" if active_only else "no steps")
        return
    names = runtime.runtime_names()
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_run()
    table_rows: list[tuple[object, ...]] = []
    row_subjects: list[str] = []
    for row in rows:
        run_serial = str(row["command_run_id"])
        pipeline_serial = str(row["pipeline_id"]) if row["pipeline_id"] is not None else ""
        state = runtime_state_label(row["job_statuses"])
        table_rows.append(
            (
                run_aliases.get(run_serial, run_serial),
                runtime_status_summary(row["job_statuses"]),
                pipeline_aliases.get(pipeline_serial, ""),
                row["source"],
                row["events"],
                artifact_counts.get(run_serial, 0),
                format_runtime_timestamp(row["first_event"]),
                format_runtime_duration(row["first_event"], row["last_event"]),
                names.get(("run", run_serial), ""),
            )
        )
        row_subjects.append("table.active_row" if state in {"active", "in progress"} else "")
    output = render_table(
        ("STEP", "STATUS", "PIPELINE", "SOURCE", "EVENTS", "ART", "STARTED", "DUR", "NAME"),
        table_rows,
        cell_subjects=("step", "", "pipeline", "", "", "", "timestamp", "timestamp", ""),
        row_subjects=row_subjects,
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    if sort_key:
        output = f"{runtime_sort_note(sort_key)}\n{output}"
    context.output(output)


def sort_step_rows(rows: list[dict], sort_key: str) -> list[dict]:
    """Return step rows ordered by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    sorters = {
        "id": lambda row: str(row["command_run_id"]),
        "serial": lambda row: str(row["command_run_id"]),
        "state": lambda row: runtime_state_label(row["job_statuses"]),
        "pipeline": lambda row: str(row["pipeline_id"] or ""),
        "source": lambda row: str(row["source"] or ""),
        "events": lambda row: int(row["events"]),
        "started": lambda row: str(row["first_event"] or ""),
    }
    return sorted(rows, key=sorters[display_key], reverse=runtime_sort_reverse(sort_key))


def show_step(context: CommandContext, step_id: str) -> None:
    """Print a compact inspection view for one pipeline step."""
    runtime = context.runtime_store("step")
    run_id = runtime.resolve_run_serial(step_id)
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    style_getter = command_context_style_getter(context)
    sections: list[str] = []
    run_row = next((row for row in runtime.runs(active_only=False) if str(row["command_run_id"]) == run_id), None)
    if run_row is not None:
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
    events = context.event_store("step").events_matching(command_run_id=run_id)
    if events:
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
    if job_id and "command.run.completed" not in topics and "command.run.failed" not in topics:
        text += f"\nNo step completion event was recorded; inspect owning job with `job {job_id}`."
    return text


def should_show_step_variable(name: str) -> bool:
    """Return whether a captured runtime variable is useful in step detail."""
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
        source = payload.get("source", "")
        return f"{step_label(style_getter, 'source')}={source} {step_label(style_getter, 'text')}={summarize_step_text(str(payload.get('text', '')))}".strip()
    if "host" in payload:
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


def step_ids(context: CompletionContext) -> list[str]:
    """Return known local step IDs for completion."""
    if context.db is None:
        return []
    return list(context.db.run_aliases().values())


def plugin() -> Commandlet:
    """Return the runtime step commandlet."""
    return Step()
