"""Background job management commandlet."""

from __future__ import annotations

import os
import signal
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.runtime_display import (
    active_listing_format,
    display_runtime_serial,
    format_runtime_timestamp,
    render_table,
    runtime_state_label,
    runtime_state_text,
    state_marker,
)

ACTIVE_STATUSES = {"queued", "claimed", "running", "pausing", "paused", "cancelling"}
JOB_ACTIONS = ("cancel", "end", "kill", "list", "show")


@commandlet(
    name="job",
    description="Manage background jobs.",
    usage="job <list|show|cancel|end|kill> [options] [id]",
    examples=("job list", "job show 1", "job cancel 1", "job end 1", "job kill --hard 1"),
    capabilities=("db.raw", "framework.console.output", "framework.job.control"),
)
@argument("action", "job operation", completion=CompletionSpec("choice", JOB_ACTIONS))
@argument("id", "job id", required=False, completion="job")
class Job(CommandletBase):
    """List, inspect, softly cancel, and end background jobs."""

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
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed = parser.parse_args(args)
        context.require_db()
        context.require_foreground("job management commands")
        validate_job_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        match parsed.action:
            case "list":
                print_jobs(context, active_only=not parsed.all, show_active=parsed.all)
            case "show":
                row = require_job(context, parsed.id)
                display_name = context.require_db().runtime_names().get(("job", str(row["id"])))
                context.output(format_job(row, display_name=display_name))
            case "cancel":
                row = require_job(context, parsed.id)
                cancel_job(context, row)
            case "end" | "kill":
                row = require_job(context, parsed.id)
                context.audit_capability("framework.job.control")
                if parsed.hard:
                    kill_job(context, row)
                else:
                    cancel_job(context, row)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and job IDs from the active database."""
        if not args:
            return list(JOB_ACTIONS)
        if len(args) == 1 and args[0] == "list":
            return ["--all"]
        if len(args) == 1 and args[0] in {"show", "cancel", "end", "kill"}:
            return job_ids(context)
        if len(args) == 1 and args[0] not in JOB_ACTIONS:
            return list(JOB_ACTIONS)
        if len(args) >= 2 and args[0] in {"show", "cancel", "end", "kill"}:
            return job_ids(context)
        return []


def print_jobs(context: CommandContext, *, active_only: bool = True, show_active: bool = False) -> None:
    """Print known jobs with newest first."""
    rows = context.require_db().jobs(active_only=active_only)
    if not rows:
        context.output("no active jobs" if active_only else "no jobs")
        return
    names = context.require_db().runtime_names()
    artifact_counts = context.require_db().artifact_counts_by_job()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        label = runtime_state_label(row["status"])
        timestamp = row["started_at"] if label in {"active", "in progress"} else row["finished_at"]
        table_rows.append(
            (
                row["id"],
                display_runtime_serial(row["serial"]),
                runtime_state_text(row["status"], timestamp, style=active_listing_format(context.vars.get_global)),
                row["pid"],
                row["status"],
                artifact_counts.get(str(row["id"]), 0),
                names.get(("job", str(row["id"])), ""),
                format_runtime_timestamp(row["started_at"]),
                format_runtime_timestamp(row["finished_at"]),
                row["command_line"],
            )
        )
    context.output(
        render_table(
            ("JOB", "SERIAL", "STATE", "PID", "STATUS", "ARTIFACTS", "NAME", "STARTED", "FINISHED", "COMMAND"),
            table_rows,
        )
    )


def validate_job_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for job management operations."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("job cancel is already cooperative; use job end --hard or job kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"job {action} does not accept --soft or --hard")


def format_job(row, *, display_name: str | None = None, show_active: bool = False, marker_style: str = "short") -> str:
    """Format one job row in the same compact format used by the old `jobs`."""
    prefix = ""
    detail = ""
    if show_active:
        label = runtime_state_label(row["status"])
        timestamp = row["started_at"] if label in {"active", "in progress"} else row["finished_at"]
        prefix, detail = state_marker(label, timestamp, style=marker_style)
    name_part = f" name={display_name}" if display_name else ""
    serial = display_runtime_serial(row["serial"])
    line = f"{prefix}#{row['id']} serial={serial} pid={row['pid']} status={row['status']}{name_part} {row['command_line']}"
    return f"{line}\n{detail}" if detail else line


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


def kill_job(context: CommandContext, row) -> None:
    """Forcefully terminate a job process and update its status."""
    db = context.require_db()
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        os.kill(int(pid), signal.SIGKILL)
    except ProcessLookupError:
        db.finish_job(int(row["id"]), "missing")
        raise ValueError(f"job {row['id']} process is not running") from None
    db.finish_job(int(row["id"]), "killed")
    context.output(f"killed job {row['id']}")


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
