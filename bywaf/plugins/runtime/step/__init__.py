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

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.view import (
    apply_runtime_new_cursor,
    filter_rows_by_events,
    filter_runtime_rows_since,
    filter_view_run_rows,
    split_since_selector,
    view_selector_candidates,
)
from bywaf.runtime_display import (
    command_context_style_getter,
    format_runtime_duration,
    format_runtime_timestamp,
    parse_runtime_list_selectors,
    render_table,
    runtime_sort_key,
    runtime_sort_note,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    terminal_table_width,
)

from .detail import show_step

STEP_SORT_KEYS = ("id", "serial", "state", "pipeline", "source", "events", "started")
STEP_TABLE_HEADERS = ("STEP", "STATUS", "PIPELINE", "SOURCE", "EVENTS", "ART", "STARTED", "DUR", "NAME")
STEP_TABLE_SUBJECTS = ("step", "", "pipeline", "", "", "", "timestamp", "timestamp", "")


@commandlet(
    name="step",
    description="List and inspect pipeline steps.",
    usage="step [--all] [--new] [field=value ...] [since=<id>] | step <id>",
    examples=("step", "step --all", "step --new", "step since=40", "step 1", "step host=192.0.2.10"),
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
        parser.add_argument("--new", action="store_true")
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
                highlight_newest=parsed.new,
                since=operation.since,
                sort_key=operation.sort,
            )
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete step IDs and list options from the active database."""
        candidates = ["--all", "--new", "sort=", "since=", *step_ids(context)]
        if not args:
            return candidates
        if args and args[-1].startswith("sort="):
            return view_selector_candidates(args[-1], STEP_SORT_KEYS)
        candidates.extend(view_selector_candidates(prefix, STEP_SORT_KEYS))
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_step_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `step` forms into an optional id plus filters."""
    if not tokens:
        return Namespace(id=None, filters={}, since="", sort="")
    if len(tokens) == 1 and "=" not in tokens[0]:
        return Namespace(id=tokens[0], filters={}, since="", sort="")
    selectors, since = split_since_selector("step", tokens)
    filters, sort = parse_runtime_list_selectors(selectors, allowed_sort_keys=STEP_SORT_KEYS, command="step")
    return Namespace(id=None, filters=filters, since=since, sort=sort)


def print_steps(
    context: CommandContext,
    *,
    active_only: bool = True,
    filters: dict[str, str] | None = None,
    highlight_newest: bool = False,
    since: str = "",
    sort_key: str = "",
) -> None:
    """Print commandlet step summaries."""
    runtime = context.runtime_store("step")
    rows = runtime.runs(active_only=active_only)
    rows = visible_step_rows(context, runtime, rows, filters=filters, since=since)
    rows, newest_alias = apply_runtime_new_cursor(context, "step", rows, highlight_newest)
    if sort_key:
        rows = sort_step_rows(rows, sort_key)
    if not rows:
        context.output(empty_step_message(active_only=active_only, filters=filters, highlight_newest=highlight_newest, since=since))
        return
    output = render_step_rows(context, rows, newest_alias=newest_alias, sort_key=sort_key, since=since)
    context.output(output)


def visible_step_rows(
    context: CommandContext,
    runtime,
    rows: list[dict],
    *,
    filters: dict[str, str] | None,
    since: str,
) -> list[dict]:
    """Return step rows visible to a list command after scope filters."""
    current_run_id = str(context.metadata.get("command_run_id") or "")
    if current_run_id:
        rows = [row for row in rows if str(row["command_run_id"]) != current_run_id]
    rows = filter_view_run_rows(context.event_store("step list"), rows)
    rows = filter_runtime_rows_since(runtime, "step", rows, since)
    if filters:
        events = context.event_store("step")
        rows = filter_rows_by_events(events, "step", rows, filters)
    return rows


def empty_step_message(
    *,
    active_only: bool,
    filters: dict[str, str] | None,
    highlight_newest: bool,
    since: str,
) -> str:
    """Return the no-results message for one step listing command."""
    if highlight_newest:
        return "no new steps"
    if filters or since:
        return "no matching steps"
    return "no active steps" if active_only else "no steps"


def render_step_rows(
    context: CommandContext,
    rows: list[dict],
    *,
    newest_alias: int,
    sort_key: str,
    since: str,
) -> str:
    """Return the rendered step table and optional list annotations."""
    runtime = context.runtime_store("step")
    table_rows, row_subjects = step_table_rows(runtime, rows, newest_alias)
    output = render_table(
        STEP_TABLE_HEADERS,
        table_rows,
        cell_subjects=STEP_TABLE_SUBJECTS,
        row_subjects=row_subjects,
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    if sort_key:
        output = f"{runtime_sort_note(sort_key)}\n{output}"
    if since:
        output = f"after step {since}\n{output}"
    return output


def step_table_rows(runtime, rows: list[dict], newest_alias: int) -> tuple[list[tuple[object, ...]], list[str]]:
    """Return table rows and row style subjects for step list output."""
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
        row_subjects.append(
            "table.active_row"
            if state in {"active", "in progress"} or int(run_aliases.get(run_serial, "0")) == newest_alias
            else ""
        )
    return table_rows, row_subjects


def sort_step_rows(rows: list[dict], sort_key: str) -> list[dict]:
    """Return step rows ordered by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    # sort_step_rows() uses this dispatch table instead of an if/elif ladder so
    # every operator-facing sort key maps visibly to its row value.
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


def step_ids(context: CompletionContext) -> list[str]:
    """Return known local step IDs for completion."""
    try:
        runtime = context.runtime_store("step completion")
    except ValueError:
        return []
    return list(runtime.run_aliases().values())


def plugin() -> Commandlet:
    """Return the runtime step commandlet."""
    return Step()
