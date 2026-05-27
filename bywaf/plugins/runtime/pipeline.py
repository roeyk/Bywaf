"""Runtime pipeline commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Lists and inspects pipeline state and history.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import shlex
from argparse import Namespace
from collections.abc import Callable, Iterable

from bywaf.event_filters import any_event_matches_payload_filters, parse_payload_filter_tokens
from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.plugins.runtime.job import cancel_job, kill_job
from bywaf.runtime_display import (
    active_listing_format,
    command_context_style_getter,
    display_runtime_serial,
    format_runtime_timestamp,
    render_table,
    runtime_state_label,
    runtime_state_text,
    state_marker,
)
from bywaf.style import styled_subject_text

PIPELINE_ACTIONS = ("attach", "cancel", "end", "kill")
REMOVED_PIPELINE_ACTIONS = {"list", "show"}
PipelineActionHandler = Callable[[CommandContext, Namespace], None]


@commandlet(
    name="pipeline",
    description="Manage pipelines.",
    usage="pipeline [--all] [field=value ...] | pipeline <id> | pipeline <cancel|end|kill|attach> [options] <id>",
    examples=(
        "pipeline",
        "pipeline --all",
        "pipeline 1",
        "pipeline cancel 1",
        "pipeline end --hard 1",
        "pipeline kill --hard 1",
        "pipeline attach 1 portscanner step=1 since=beginning",
    ),
    capabilities=("framework.console.output", "framework.pipeline.control", "framework.job.control"),
)
@argument("action", "pipeline operation", required=False, completion=CompletionSpec("choice", PIPELINE_ACTIONS))
@argument("id", "pipeline id", required=False, completion="pipeline")
class Pipeline(CommandletBase):
    """List, inspect, softly cancel, and end pipelines."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one pipeline-management operation."""
        parser = self.parser()
        if args and args[0] == "attach":
            # `pipeline attach` has a commandlet tail after its selectors. Parse
            # it separately so commandlet arguments are not mistaken for
            # pipeline-management options.
            attach_pipeline(context, args[1:])
            return ()
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        operation = parse_pipeline_operation(tokens)
        parsed.action = operation.action
        parsed.id = operation.id
        parsed.filters = operation.filters
        context.require_foreground("pipeline management commands")
        validate_pipeline_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        pipeline_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and pipeline IDs from the active database."""
        if not args:
            return ["--all", "--page", *pipeline_ids(context), *PIPELINE_ACTIONS]
        if len(args) == 1 and args[0] == "attach":
            return pipeline_ids(context)
        if len(args) == 1 and args[0] in {"cancel", "end", "kill"}:
            return pipeline_ids(context)
        if len(args) == 1:
            return [candidate for candidate in ["--all", "--page", *pipeline_ids(context), *PIPELINE_ACTIONS] if candidate.startswith(prefix)]
        if args and args[0] == "attach":
            return attach_candidates(context, args, prefix)
        if len(args) >= 2 and args[0] in {"cancel", "end", "kill"}:
            return pipeline_ids(context)
        return []


def parse_pipeline_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `pipeline` forms into the internal action/id/filter shape."""
    if not tokens:
        return Namespace(action="list", id=None, filters={})
    first, rest = tokens[0], tokens[1:]
    if first in REMOVED_PIPELINE_ACTIONS:
        raise ValueError(
            "usage: pipeline [--all] [field=value ...] | pipeline <id> | pipeline <cancel|end|kill|attach> [options] <id>"
        )
    if first in {"cancel", "end", "kill"}:
        if not rest:
            raise ValueError(f"pipeline {first} requires a pipeline id")
        return Namespace(action=first, id=rest[0], filters=parse_payload_filter_tokens(rest[1:]))
    if "=" not in first and not rest:
        return Namespace(action="show", id=first, filters={})
    return Namespace(action="list", id=None, filters=parse_payload_filter_tokens(tokens))


def pipeline_action_handlers() -> dict[str, PipelineActionHandler]:
    """Return pipeline action handlers keyed by action name."""
    return {
        "cancel": cancel_pipeline_action,
        "end": end_pipeline_action,
        "kill": end_pipeline_action,
        "list": list_pipeline_action,
        "show": show_pipeline_action,
    }


def list_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline list`."""
    print_pipelines(
        context,
        active_only=not parsed.all and not parsed.filters,
        show_active=parsed.all,
        page=parsed.page,
        filters=parsed.filters,
    )


def show_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline show`."""
    row = require_pipeline(context, parsed.id)
    runtime = context.runtime_store("pipeline show")
    display_name = runtime.runtime_names().get(("pipeline", str(row["pipeline_id"])))
    alias = runtime.pipeline_aliases().get(str(row["pipeline_id"]))
    context.output(
        format_pipeline(
            row,
            display_name=display_name,
            alias=alias,
            style_getter=command_context_style_getter(context),
        )
    )


def cancel_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline cancel`."""
    cancel_pipeline(context, parsed.id)


def end_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline end` or `pipeline kill`."""
    if parsed.hard:
        kill_pipeline(context, parsed.id)
    else:
        cancel_pipeline(context, parsed.id)


def print_pipelines(
    context: CommandContext,
    *,
    active_only: bool = True,
    show_active: bool = False,
    page: bool = False,
    filters: dict[str, str] | None = None,
) -> None:
    """Print active pipelines by default, or all pipelines when requested."""
    runtime = context.runtime_store("pipeline list")
    rows = runtime.pipelines(active_only=active_only)
    if filters:
        events = context.event_store("pipeline list")
        rows = [
            row
            for row in rows
            if any_event_matches_payload_filters(
                events.events_matching(pipeline_id=str(row["pipeline_id"]), limit=10000),
                filters,
            )
        ]
    if not rows:
        context.output("no matching pipelines" if filters else "no active pipelines" if active_only else "no pipelines")
        return
    names = runtime.runtime_names()
    aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_pipeline()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        statuses = row["job_statuses"] or "unknown"
        label = runtime_state_label(statuses)
        timestamp = row["first_seen"] if label in {"active", "in progress"} else row["last_seen"]
        table_rows.append(
            (
                aliases.get(str(row["pipeline_id"]), str(row["pipeline_id"])),
                display_runtime_serial(row["pipeline_id"]),
                runtime_state_text(statuses, timestamp, style=active_listing_format(context.vars.get_global)),
                names.get(("pipeline", str(row["pipeline_id"])), ""),
                row["job_id"],
                statuses,
                row["runs"],
                row["events"],
                artifact_counts.get(str(row["pipeline_id"]), 0),
                format_runtime_timestamp(row["first_seen"]),
                format_runtime_timestamp(row["last_seen"]),
            )
        )
    output = render_table(
        ("PIPELINE", "SERIAL", "STATE", "NAME", "JOB", "STATUS", "STEPS", "EVENTS", "ARTIFACTS", "FIRST", "LAST"),
        table_rows,
        cell_subjects=("pipeline", "serial", "", "", "job", "", "", "", "", "timestamp", "timestamp"),
        style_getter=command_context_style_getter(context),
    )
    if page:
        context.page_text(output)
    else:
        context.output(output)


def validate_pipeline_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for pipeline management operations."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("pipeline cancel is already cooperative; use pipeline end --hard or pipeline kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"pipeline {action} does not accept --soft or --hard")


def format_pipeline(
    row,
    *,
    display_name: str | None = None,
    alias: str | None = None,
    show_active: bool = False,
    marker_style: str = "short",
    style_getter=None,
) -> str:
    """Format one pipeline summary row."""
    statuses = row["job_statuses"] or "unknown"
    prefix = ""
    detail = ""
    if show_active:
        label = runtime_state_label(statuses)
        timestamp = row["first_seen"] if label in {"active", "in progress"} else row["last_seen"]
        prefix, detail = state_marker(label, timestamp, style=marker_style)
    name_part = f" name={display_name}" if display_name else ""
    pipeline_id = alias or row["pipeline_id"]
    pipeline_id = styled_subject_text(style_getter, "pipeline", pipeline_id) if style_getter else pipeline_id
    serial = display_runtime_serial(row["pipeline_id"])
    serial = styled_subject_text(style_getter, "serial", serial) if style_getter else serial
    line = (
        f"{prefix}pipeline={pipeline_id} serial={serial}"
        f"{name_part} job={row['job_id']} status={statuses} steps={row['runs']} events={row['events']}"
    )
    return f"{line}\n{detail}" if detail else line


def require_pipeline(context: CommandContext, pipeline_id: str | None):
    """Return a pipeline row or raise a user-facing error."""
    if not pipeline_id:
        raise ValueError("pipeline id is required")
    runtime = context.runtime_store("pipeline")
    resolved = runtime.resolve_pipeline_serial(pipeline_id)
    for row in runtime.pipelines():
        if row["pipeline_id"] == resolved:
            return row
    raise ValueError(f"unknown pipeline: {pipeline_id}")


def cancel_pipeline(context: CommandContext, pipeline_id: str | None) -> None:
    """Request cooperative cancellation for a pipeline and its known jobs."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    runtime = context.runtime_store("pipeline cancel")
    runtime.request_cancellation("pipeline", row["pipeline_id"])
    for job in runtime.jobs_for_pipeline(row["pipeline_id"]):
        cancel_job(context, job)
    context.output(f"cancel requested for pipeline {row['pipeline_id']}")


def kill_pipeline(context: CommandContext, pipeline_id: str | None) -> None:
    """Hard-kill known jobs associated with a pipeline."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    jobs = context.runtime_store("pipeline kill").jobs_for_pipeline(row["pipeline_id"])
    if not jobs:
        raise ValueError(f"pipeline {row['pipeline_id']} has no associated jobs")
    for job in jobs:
        kill_job(context, job)
    context.output(f"killed pipeline {row['pipeline_id']}")


def attach_pipeline(context: CommandContext, args: list[str]) -> None:
    """Attach one commandlet to an existing pipeline as a background job."""
    context.require_foreground("pipeline attach")
    if len(args) < 2:
        raise ValueError("usage: pipeline attach <pipeline-id> <commandlet> [step=<step-id>] [since=beginning|now] [args...]")
    pipeline_id, commandlet_name, *tail = args
    runtime = context.runtime_store("pipeline attach")
    resolved_pipeline_id = runtime.resolve_pipeline_serial(pipeline_id)
    selectors, commandlet_args = parse_attach_tail(tail)
    runner = context.metadata.get("runner")
    if runner is None:
        raise ValueError("pipeline attach requires a live runner")
    command_line = " ".join(shlex.quote(token) for token in [commandlet_name, *commandlet_args])
    # The runner owns the attached background execution so it can replay prior
    # pipeline events from the requested cursor and keep runtime metadata stable.
    event = runner.start_attached_pipeline(
        resolved_pipeline_id,
        command_line,
        upstream_run_id=(
            runtime.resolve_run_serial(selectors["step"]) if "step" in selectors else None
        ),
        since_cursor=selectors.get("since", "beginning"),
    )
    context.output(f"attached job={event.payload['job_id']} pipeline={resolved_pipeline_id} command={command_line}")


def parse_attach_tail(tokens: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split attach selectors from commandlet arguments."""
    selectors: dict[str, str] = {}
    commandlet_args: list[str] = []
    for token in tokens:
        # Only these selectors belong to pipeline attach. Everything else is
        # passed through verbatim to the commandlet being attached.
        if token.startswith("step="):
            selectors["step"] = require_selector_value(token)
        elif token.startswith("since="):
            value = require_selector_value(token)
            if value not in {"beginning", "now"}:
                raise ValueError("since= must be beginning or now")
            selectors["since"] = value
        else:
            commandlet_args.append(token)
    return selectors, commandlet_args


def require_selector_value(token: str) -> str:
    """Return the value from a non-empty key=value selector."""
    _key, value = token.split("=", 1)
    if not value:
        raise ValueError(f"{token} requires a value")
    return value


def attach_candidates(context: CompletionContext, args: list[str], prefix: str) -> list[str]:
    """Complete attach pipeline id, commandlet name, and attach selectors."""
    if len(args) == 2:
        return pipeline_ids(context)
    if len(args) == 3:
        names = context.metadata.get("commandlets", ())
        return [name for name in names if str(name).startswith(prefix)]
    if prefix.startswith("step="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"step={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
    if prefix.startswith("since="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"since={value}" for value in ("beginning", "now") if value.startswith(value_prefix)]
    return ["step=", "since="]


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.pipeline_aliases().values(), key=int)


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.run_aliases().values(), key=int)


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Pipeline()
