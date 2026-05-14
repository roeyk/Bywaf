"""Pipeline management commandlet."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.plugins.runtime.job import cancel_job, kill_job

PIPELINE_ACTIONS = ("cancel", "kill", "list", "show")


@commandlet(
    name="pipeline",
    description="Manage pipelines.",
    usage="pipeline <list|show|cancel|kill> [options] [id]",
    examples=("pipeline list", "pipeline show pipeline-...", "pipeline cancel pipeline-..."),
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
        parser.add_argument("action", choices=PIPELINE_ACTIONS)
        parser.add_argument("id", nargs="?")
        parser.add_argument("--force", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground("pipeline management commands")
        match parsed.action:
            case "list":
                print_pipelines(context)
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
        if len(args) == 1 and args[0] in {"show", "cancel", "kill"}:
            return pipeline_ids(context)
        if len(args) == 1 and args[0] not in PIPELINE_ACTIONS:
            return list(PIPELINE_ACTIONS)
        if len(args) >= 2 and args[0] in {"show", "cancel", "kill"}:
            return pipeline_ids(context)
        return []


def print_pipelines(context: CommandContext) -> None:
    """Print all known pipelines with newest first."""
    for row in context.require_db().pipelines():
        context.output(format_pipeline(row))


def format_pipeline(row) -> str:
    """Format one pipeline summary row."""
    return f"{row['pipeline_id']} job={row['job_id']} runs={row['runs']} events={row['events']}"


def require_pipeline(context: CommandContext, pipeline_id: str | None):
    """Return a pipeline row or raise a user-facing error."""
    if not pipeline_id:
        raise ValueError("pipeline id is required")
    for row in context.require_db().pipelines():
        if row["pipeline_id"] == pipeline_id:
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


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return [row["pipeline_id"] for row in context.db.pipelines()]


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Pipeline()
