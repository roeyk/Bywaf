"""Background job management commandlet."""

from __future__ import annotations

import os
import signal
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet

JOB_ACTIONS = ("cancel", "kill", "list", "show")


@commandlet(
    name="job",
    description="Manage background jobs.",
    usage="job <list|show|cancel|kill> [options] [id]",
    examples=("job list", "job show 1", "job cancel 1", "job kill --force 1"),
    capabilities=("db.raw", "framework.console.output", "framework.job.control"),
)
@argument("action", "job operation", completion=CompletionSpec("choice", JOB_ACTIONS))
@argument("id", "job id", required=False, completion="job")
class Job(CommandletBase):
    """List, inspect, softly cancel, and hard-kill background jobs."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one job-management operation."""
        parser = self.parser()
        parser.add_argument("action", choices=JOB_ACTIONS)
        parser.add_argument("id", nargs="?")
        parser.add_argument("--force", action="store_true")
        parsed = parser.parse_args(args)
        context.require_db()
        context.require_foreground("job management commands")
        match parsed.action:
            case "list":
                print_jobs(context)
            case "show":
                row = require_job(context, parsed.id)
                context.output(format_job(row))
            case "cancel":
                row = require_job(context, parsed.id)
                cancel_job(context, row)
            case "kill":
                row = require_job(context, parsed.id)
                context.audit_capability("framework.job.control")
                kill_job(context, row, force=parsed.force)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and job IDs from the active database."""
        if not args:
            return list(JOB_ACTIONS)
        if len(args) == 1 and args[0] in {"show", "cancel", "kill"}:
            return job_ids(context)
        if len(args) == 1 and args[0] not in JOB_ACTIONS:
            return list(JOB_ACTIONS)
        if len(args) >= 2 and args[0] in {"show", "cancel", "kill"}:
            return job_ids(context)
        return []


def print_jobs(context: CommandContext) -> None:
    """Print all known jobs with newest first."""
    for row in context.require_db().jobs():
        context.output(format_job(row))


def format_job(row) -> str:
    """Format one job row in the same compact format used by the old `jobs`."""
    return f"#{row['id']} pid={row['pid']} status={row['status']} {row['command_line']}"


def require_job(context: CommandContext, job_id: str | None):
    """Return a job row or raise a user-facing error."""
    db = context.require_db()
    if not job_id:
        raise ValueError("job id is required")
    try:
        numeric_id = int(job_id)
    except ValueError as exc:
        raise ValueError(f"invalid job id: {job_id}") from exc
    row = db.job(numeric_id)
    if row is None:
        raise ValueError(f"unknown job: {job_id}")
    return row


def kill_job(context: CommandContext, row, *, force: bool) -> None:
    """Send SIGTERM or SIGKILL to a job process and update its status."""
    db = context.require_db()
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        db.finish_job(int(row["id"]), "missing")
        raise ValueError(f"job {row['id']} process is not running") from None
    status = "killed" if force else "terminated"
    db.finish_job(int(row["id"]), status)
    context.output(f"{status} job {row['id']}")


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    if context.db is None:
        return []
    return [str(row["id"]) for row in context.db.jobs()]


def cancel_job(context: CommandContext, row) -> None:
    """Request cooperative cancellation for one job row."""
    db = context.require_db()
    context.audit_capability("framework.job.control")
    db.request_cancellation("job", str(row["id"]))
    db.update_job_status(int(row["id"]), "cancelling")
    context.output(f"cancel requested for job {row['id']}")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Job()
