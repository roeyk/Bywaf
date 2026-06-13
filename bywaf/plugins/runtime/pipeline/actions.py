"""Pipeline list/show/control action handlers.

Used by: `runtime.pipeline.Pipeline.run()` after command parsing resolves the
requested pipeline action and selector values.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import cancel_job, kill_job
from bywaf.plugins.runtime.pipeline.view import (
    format_pipeline,
    format_pipeline_artifacts,
    format_pipeline_hints,
    format_pipeline_jobs,
    format_pipeline_steps,
    print_pipelines,
)
from bywaf.runtime.display import command_context_style_getter

PipelineActionHandler = Callable[[CommandContext, Namespace], None]


def pipeline_action_handlers() -> dict[str, PipelineActionHandler]:
    """Return pipeline action handlers keyed by action name.

    Called by: `Pipeline.run()`, which uses this dispatch table instead of an
    `if`/`elif` action ladder.
    """
    # Dispatch table for Pipeline.run(): each normalized action token maps to
    # the handler that lists, shows, cancels, or ends a pipeline.
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
        active_only=False,
        show_active=parsed.all,
        page=parsed.page,
        filters=parsed.filters,
        highlight_newest=parsed.new,
        since=parsed.since,
        sort_key=parsed.sort,
    )


def show_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline show`."""
    row = require_pipeline(context, parsed.id)
    runtime = context.runtime_store("pipeline show")
    display_name = runtime.runtime_names().get(("pipeline", str(row["pipeline_id"])))
    alias = runtime.pipeline_aliases().get(str(row["pipeline_id"]))
    style_getter = command_context_style_getter(context)
    # Pipeline detail is intentionally sectioned: summary, inspection hints,
    # artifacts, related jobs, and related steps can evolve independently.
    sections = [
        format_pipeline(
            row,
            display_name=display_name,
            alias=alias,
            style_getter=style_getter,
        ),
        format_pipeline_hints(context, str(row["pipeline_id"])),
        format_pipeline_artifacts(context, str(row["pipeline_id"]), alias or str(row["pipeline_id"])),
        format_pipeline_jobs(context, str(row["pipeline_id"])),
        format_pipeline_steps(context, str(row["pipeline_id"])),
    ]
    context.output("\n\n".join(section for section in sections if section))


def cancel_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline cancel`."""
    cancel_pipeline(context, parsed.id)


def end_pipeline_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `pipeline end` or `pipeline kill`."""
    if parsed.hard:
        kill_pipeline(context, parsed.id)
    else:
        cancel_pipeline(context, parsed.id)


def validate_pipeline_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for pipeline management operations."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("pipeline cancel is already cooperative; use pipeline end --hard or pipeline kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"pipeline {action} does not accept --soft or --hard")


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
