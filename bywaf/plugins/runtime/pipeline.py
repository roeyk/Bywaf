"""Pipeline management commandlet."""

from __future__ import annotations

import shlex
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.plugins.runtime.job import cancel_job, kill_job
from bywaf.runtime_display import active_listing_format, format_runtime_timestamp, render_table, runtime_state_label, runtime_state_text, state_marker

PIPELINE_ACTIONS = ("attach", "cancel", "kill", "list", "show")


@commandlet(
    name="pipeline",
    description="Manage pipelines.",
    usage="pipeline <list|show|cancel|kill|attach> [options] [id]",
    examples=(
        "pipeline list",
        "pipeline list --all",
        "pipeline show 1",
        "pipeline cancel 1",
        "pipeline attach 1 portscanner run=1 since=beginning",
    ),
    capabilities=("db.raw", "framework.console.output", "framework.pipeline.control", "framework.job.control"),
)
@argument("action", "pipeline operation", completion=CompletionSpec("choice", PIPELINE_ACTIONS))
@argument("id", "pipeline id", required=False, completion="pipeline")
class Pipeline(CommandletBase):
    """List, inspect, softly cancel, and hard-kill pipelines."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one pipeline-management operation."""
        parser = self.parser()
        if args and args[0] == "attach":
            attach_pipeline(context, args[1:])
            return ()
        parser.add_argument("action", choices=PIPELINE_ACTIONS)
        parser.add_argument("id", nargs="?")
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--force", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground("pipeline management commands")
        match parsed.action:
            case "list":
                print_pipelines(context, active_only=not parsed.all, show_active=parsed.all)
            case "show":
                row = require_pipeline(context, parsed.id)
                context.output(format_pipeline(row))
            case "cancel":
                cancel_pipeline(context, parsed.id)
            case "kill":
                kill_pipeline(context, parsed.id, force=parsed.force)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and pipeline IDs from the active database."""
        if not args:
            return list(PIPELINE_ACTIONS)
        if len(args) == 1 and args[0] == "attach":
            return pipeline_ids(context)
        if len(args) == 1 and args[0] == "list":
            return ["--all"]
        if len(args) == 1 and args[0] in {"show", "cancel", "kill"}:
            return pipeline_ids(context)
        if len(args) == 1 and args[0] not in PIPELINE_ACTIONS:
            return list(PIPELINE_ACTIONS)
        if args and args[0] == "attach":
            return attach_candidates(context, args, prefix)
        if args and args[0] == "list":
            return ["--all"] if "--all".startswith(prefix) else []
        if len(args) >= 2 and args[0] in {"show", "cancel", "kill"}:
            return pipeline_ids(context)
        return []


def print_pipelines(context: CommandContext, *, active_only: bool = True, show_active: bool = False) -> None:
    """Print active pipelines by default, or all pipelines when requested."""
    rows = context.require_db().pipelines(active_only=active_only)
    if not rows:
        context.output("no active pipelines" if active_only else "no pipelines")
        return
    db = context.require_db()
    names = db.runtime_names()
    aliases = db.pipeline_aliases()
    artifact_counts = db.artifact_counts_by_pipeline()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        statuses = row["job_statuses"] or "unknown"
        label = runtime_state_label(statuses)
        timestamp = row["first_seen"] if label in {"active", "in progress"} else row["last_seen"]
        table_rows.append(
            (
                aliases.get(str(row["pipeline_id"]), str(row["pipeline_id"])),
                row["pipeline_id"],
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
    context.output(
        render_table(
            ("PIPELINE", "SERIAL", "STATE", "NAME", "JOB", "STATUS", "RUNS", "EVENTS", "ARTIFACTS", "FIRST", "LAST"),
            table_rows,
        )
    )


def format_pipeline(
    row,
    *,
    display_name: str | None = None,
    alias: str | None = None,
    show_active: bool = False,
    marker_style: str = "short",
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
    line = (
        f"{prefix}pipeline={alias or row['pipeline_id']} serial={row['pipeline_id']}"
        f"{name_part} job={row['job_id']} status={statuses} runs={row['runs']} events={row['events']}"
    )
    return f"{line}\n{detail}" if detail else line


def require_pipeline(context: CommandContext, pipeline_id: str | None):
    """Return a pipeline row or raise a user-facing error."""
    if not pipeline_id:
        raise ValueError("pipeline id is required")
    resolved = context.require_db().resolve_pipeline_serial(pipeline_id)
    for row in context.require_db().pipelines():
        if row["pipeline_id"] == resolved:
            return row
    raise ValueError(f"unknown pipeline: {pipeline_id}")


def cancel_pipeline(context: CommandContext, pipeline_id: str | None) -> None:
    """Request cooperative cancellation for a pipeline and its known jobs."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    db = context.require_db()
    db.request_cancellation("pipeline", row["pipeline_id"])
    for job in db.jobs_for_pipeline(row["pipeline_id"]):
        cancel_job(context, job)
    context.output(f"cancel requested for pipeline {row['pipeline_id']}")


def kill_pipeline(context: CommandContext, pipeline_id: str | None, *, force: bool) -> None:
    """Hard-kill known jobs associated with a pipeline."""
    row = require_pipeline(context, pipeline_id)
    context.audit_capability("framework.pipeline.control")
    jobs = context.require_db().jobs_for_pipeline(row["pipeline_id"])
    if not jobs:
        raise ValueError(f"pipeline {row['pipeline_id']} has no associated jobs")
    for job in jobs:
        kill_job(context, job, force=force)
    context.output(f"killed pipeline {row['pipeline_id']}" if force else f"terminated pipeline {row['pipeline_id']}")


def attach_pipeline(context: CommandContext, args: list[str]) -> None:
    """Attach one commandlet to an existing pipeline as a background job."""
    context.require_foreground("pipeline attach")
    if len(args) < 2:
        raise ValueError("usage: pipeline attach <pipeline-id> <commandlet> [run=<run-id>] [since=beginning|now] [args...]")
    pipeline_id, commandlet_name, *tail = args
    resolved_pipeline_id = context.require_db().resolve_pipeline_serial(pipeline_id)
    selectors, commandlet_args = parse_attach_tail(tail)
    runner = context.metadata.get("runner")
    if runner is None:
        raise ValueError("pipeline attach requires a live runner")
    command_line = " ".join(shlex.quote(token) for token in [commandlet_name, *commandlet_args])
    event = runner.start_attached_pipeline(
        resolved_pipeline_id,
        command_line,
        upstream_run_id=(
            context.require_db().resolve_run_serial(selectors["run"]) if "run" in selectors else None
        ),
        since_cursor=selectors.get("since", "beginning"),
    )
    context.output(f"attached job={event.payload['job_id']} pipeline={resolved_pipeline_id} command={command_line}")


def parse_attach_tail(tokens: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split attach selectors from commandlet arguments."""
    selectors: dict[str, str] = {}
    commandlet_args: list[str] = []
    for token in tokens:
        if token.startswith("run="):
            selectors["run"] = require_selector_value(token)
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
    if prefix.startswith("run="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"run={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
    if prefix.startswith("since="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"since={value}" for value in ("beginning", "now") if value.startswith(value_prefix)]
    return ["run=", "since="]


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.pipeline_aliases().values(), key=int)


def run_ids(context: CompletionContext) -> list[str]:
    """Return command-run IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.run_aliases().values(), key=int)


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Pipeline()
