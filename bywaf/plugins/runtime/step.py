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

STEP_SORT_KEYS = ("id", "serial", "state", "pipeline", "source", "events", "started")


@commandlet(
    name="step",
    description="List and inspect pipeline steps.",
    usage="step [--all] [field=value ...] | step <id>",
    examples=("step", "step --all", "step 1", "step host=192.0.2.10"),
    capabilities=("framework.console.output",),
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
    """Print variable snapshot and events for one pipeline step."""
    runtime = context.runtime_store("step")
    run_id = runtime.resolve_run_serial(step_id)
    rows = runtime.command_run_var_rows(run_id)
    if rows:
        context.output("Variables:\n" + "\n".join(f"  {row['name']}={row['value']}" for row in rows))
    events = context.event_store("step").events_matching(command_run_id=run_id)
    if events:
        context.output("\n".join(format_step_event(event) for event in events))


def format_step_event(event: Event) -> str:
    """Render one step event line without relying on REPL internals."""
    return f"{event.id}: {event.topic} {format_step_payload(event.payload)}".rstrip()


def format_step_payload(payload: object) -> str:
    """Render event payload values compactly for step inspection."""
    if not isinstance(payload, dict):
        return str(payload)
    if "host" in payload:
        parts = [str(payload.get("host", ""))]
        if payload.get("port") is not None:
            parts[-1] = f"{parts[-1]}:{payload['port']}"
        return " ".join(part for part in parts if part)
    return " ".join(f"{key}={value}" for key, value in payload.items())


def step_ids(context: CompletionContext) -> list[str]:
    """Return known local step IDs for completion."""
    if context.db is None:
        return []
    return list(context.db.run_aliases().values())


def plugin() -> Commandlet:
    """Return the runtime step commandlet."""
    return Step()
