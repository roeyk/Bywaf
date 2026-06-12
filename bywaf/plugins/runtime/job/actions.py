"""Action handlers for the runtime `job` command.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.artifact.summary import artifact_events_for_job, render_artifact_summary
from bywaf.plugins.runtime.job.control import cancel_job, kill_job, require_job
from bywaf.plugins.runtime.job.display import format_job, latest_job_args, print_jobs
from bywaf.runtime_display import command_context_style_getter

JobActionHandler = Callable[[CommandContext, Namespace], None]


def job_action_handlers() -> dict[str, JobActionHandler]:
    """Return job action handlers keyed by action name.

    Called by: `Job.run()`, which uses this dispatch table instead of an
    `if`/`elif` action ladder.
    """
    # Dispatch table for Job.run(): each normalized action token maps to the
    # command handler that performs validation, rendering, or job control.
    return {
        "cancel": cancel_job_action,
        "end": end_job_action,
        "kill": end_job_action,
        "list": list_job_action,
        "show": show_job_action,
    }


def list_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job list`."""
    print_jobs(
        context,
        active_only=False,
        show_active=parsed.all,
        page=parsed.page,
        filters=parsed.filters,
        row_filters=parsed.row_filters,
        highlight_newest=parsed.new,
        since=parsed.since,
        sort_key=parsed.sort,
    )


def show_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job show`."""
    row = require_job(context, parsed.id)
    display_name = context.runtime_store("job show").runtime_names().get(("job", str(row["id"])))
    # Detail output combines the job lifecycle block with artifact summary
    # context so operators can jump from `job N` to artifact inspection.
    sections = [
        format_job(
            row,
            display_name=display_name,
            args=latest_job_args(context, row["id"]),
            style_getter=command_context_style_getter(context),
        ),
        render_artifact_summary(
            context,
            artifact_events_for_job(context, row["id"]),
            inspect_command=f"artifact list job={row['id']}",
        ),
    ]
    context.output("\n\n".join(section for section in sections if section))


def cancel_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job cancel`."""
    cancel_job(context, require_job(context, parsed.id))


def end_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job end` or `job kill`."""
    row = require_job(context, parsed.id)
    context.audit_capability("framework.job.control")
    if parsed.hard:
        kill_job(context, row)
    else:
        cancel_job(context, row)
