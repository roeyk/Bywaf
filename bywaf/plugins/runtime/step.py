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

from bywaf.event_filters import any_event_matches_payload_filters, parse_payload_filter_tokens
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.runtime_display import (
    active_listing_format,
    display_runtime_serial,
    format_runtime_timestamp,
    render_table,
    runtime_state_label,
    runtime_state_text,
)


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
            print_steps(context, active_only=not parsed.all and not operation.filters, filters=operation.filters)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete step IDs and list options from the active database."""
        candidates = ["--all", *step_ids(context)]
        if not args:
            return candidates
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_step_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `step` forms into an optional id plus filters."""
    if not tokens:
        return Namespace(id=None, filters={})
    if len(tokens) == 1 and "=" not in tokens[0]:
        return Namespace(id=tokens[0], filters={})
    return Namespace(id=None, filters=parse_payload_filter_tokens(tokens))


def print_steps(context: CommandContext, *, active_only: bool = True, filters: dict[str, str] | None = None) -> None:
    """Print commandlet step summaries."""
    runtime = context.runtime_store("step")
    rows = runtime.runs(active_only=active_only)
    if filters:
        events = context.event_store("step")
        rows = [
            row
            for row in rows
            if any_event_matches_payload_filters(
                events.events_matching(command_run_id=str(row["command_run_id"]), limit=10000),
                filters,
            )
        ]
    if not rows:
        context.output("no matching steps" if filters else "no active steps" if active_only else "no steps")
        return
    marker_style = active_listing_format(context.vars.get_global)
    names = runtime.runtime_names()
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_run()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        run_serial = str(row["command_run_id"])
        pipeline_serial = str(row["pipeline_id"]) if row["pipeline_id"] is not None else ""
        label = runtime_state_label(row["job_statuses"])
        timestamp = row["first_event"] if label in {"active", "in progress"} else row["last_event"]
        table_rows.append(
            (
                run_aliases.get(run_serial, run_serial),
                display_runtime_serial(run_serial),
                runtime_state_text(row["job_statuses"], timestamp, style=marker_style),
                names.get(("run", run_serial), ""),
                pipeline_aliases.get(pipeline_serial, ""),
                display_runtime_serial(pipeline_serial),
                row["source"],
                row["events"],
                artifact_counts.get(run_serial, 0),
                format_runtime_timestamp(row["first_event"]),
                format_runtime_timestamp(row["last_event"]),
            )
        )
    context.output(
        render_table(
            ("STEP", "SERIAL", "STATE", "NAME", "PIPELINE", "PIPELINE_SERIAL", "SOURCE", "EVENTS", "ARTIFACTS", "FIRST", "LAST"),
            table_rows,
        )
    )


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
