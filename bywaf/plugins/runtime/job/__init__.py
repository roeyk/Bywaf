"""Runtime job commandlet.

Provides the bundled `runtime.job` plugin implementation and CommandSpec
metadata. Operators use this commandlet to list, inspect, and control
background jobs.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
- Runtime control plugins: import the re-exported job lookup/control helpers.
"""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.plugins.runtime.job import control as _job_control
from bywaf.plugins.runtime.job.actions import job_action_handlers
from bywaf.plugins.runtime.job.control import cancel_job, kill_job, require_job
from bywaf.plugins.runtime.job.display import (
    format_job,
    format_job_command,
    job_ids,
    latest_job_args,
    print_jobs,
    sort_job_rows,
)
from bywaf.plugins.runtime.job.parsing import (
    JOB_ACTIONS,
    JOB_SORT_KEYS,
    job_completion_candidates,
    parse_job_operation,
    validate_job_mode,
)

ACTIVE_STATUSES = {"queued", "claimed", "running", "pausing", "paused", "cancelling"}

# Compatibility patch seam: tests still patch `bywaf.plugins.runtime.job.os.kill`;
# alias the control module's `os` object so those patches continue to affect
# `control.kill_job()`.
os = _job_control.os

__all__ = [
    "ACTIVE_STATUSES",
    "JOB_ACTIONS",
    "JOB_SORT_KEYS",
    "Job",
    "cancel_job",
    "format_job",
    "format_job_command",
    "job_ids",
    "kill_job",
    "latest_job_args",
    "parse_job_operation",
    "plugin",
    "print_jobs",
    "require_job",
    "sort_job_rows",
    "validate_job_mode",
]


@commandlet(
    name="job",
    description="Manage background jobs.",
    usage="job [--all] [--new] [field=value ...] [since=<id>] | job <id> | job <cancel|end|kill> [options] <id>",
    examples=("job", "job --all", "job --new", "job since=120", "job 1", "job cancel 1", "job end 1", "job kill --hard 1"),
)
@argument("action", "job operation", required=False, completion=CompletionSpec("choice", JOB_ACTIONS))
@argument("id", "job id", required=False, completion="job")
class Job(CommandletBase):
    """List, inspect, softly cancel, and end background jobs."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify job list/show separately from job-control operations."""
        try:
            operation = parse_job_operation([arg for arg in args if arg not in {"--all", "--new", "--page"}])
        except ValueError:
            return ("view",)
        return ("write",) if operation.action in JOB_ACTIONS else ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one job-management operation."""
        del input_events
        parser = self.parser()
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed, tokens = parser.parse_known_intermixed_args(args)
        operation = parse_job_operation(tokens)
        parsed.action = operation.action
        parsed.id = operation.id
        parsed.filters = operation.filters
        parsed.row_filters = operation.row_filters
        parsed.since = operation.since
        parsed.sort = operation.sort
        context.require_foreground("job management commands")
        validate_job_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        # `job_action_handlers()` returns the action dispatch table used here
        # instead of an if/elif ladder over list/show/cancel/end/kill.
        job_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and job IDs from the active database."""
        return job_completion_candidates(args, prefix, job_ids(context))


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Job()
