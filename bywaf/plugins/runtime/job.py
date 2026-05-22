"""Runtime job commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Lists and inspects background job state.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import os
import signal
from argparse import Namespace
from collections.abc import Callable, Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.runtime_display import (
    active_listing_format,
    commandlet_from_command_line,
    display_runtime_serial,
    format_runtime_timestamp,
    render_table,
    runtime_state_label,
    runtime_state_text,
    state_marker,
)

ACTIVE_STATUSES = {"queued", "claimed", "running", "pausing", "paused", "cancelling"}
JOB_ACTIONS = ("cancel", "end", "kill", "list", "show")
JobActionHandler = Callable[[CommandContext, Namespace], None]


@commandlet(
    name="job",
    description="Manage background jobs.",
    usage="job <list|show|cancel|end|kill> [options] [id]",
    examples=("job list", "job show 1", "job cancel 1", "job end 1", "job kill --hard 1"),
    capabilities=("framework.console.output", "framework.job.control"),
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
        parser.add_argument("--page", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed = parser.parse_intermixed_args(args)
        context.require_foreground("job management commands")
        validate_job_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        job_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and job IDs from the active database."""
        if not args:
            return list(JOB_ACTIONS)
        if len(args) == 1 and args[0] == "list":
            return ["--all", "--page"]
        if len(args) == 1 and args[0] in {"show", "cancel", "end", "kill"}:
            return job_ids(context)
        if len(args) == 1 and args[0] not in JOB_ACTIONS:
            return list(JOB_ACTIONS)
        if len(args) >= 2 and args[0] in {"show", "cancel", "end", "kill"}:
            return job_ids(context)
        return []


def job_action_handlers() -> dict[str, JobActionHandler]:
    """Return job action handlers keyed by action name."""
    return {
        "cancel": cancel_job_action,
        "end": end_job_action,
        "kill": end_job_action,
        "list": list_job_action,
        "show": show_job_action,
    }


def list_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job list`."""
    print_jobs(context, active_only=not parsed.all, show_active=parsed.all, page=parsed.page)


def show_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job show`."""
    row = require_job(context, parsed.id)
    display_name = context.runtime_store("job show").runtime_names().get(("job", str(row["id"])))
    context.output(format_job(row, display_name=display_name))


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


def print_jobs(context: CommandContext, *, active_only: bool = True, show_active: bool = False, page: bool = False) -> None:
    """Print known jobs with newest first."""
    runtime = context.runtime_store("job list")
    rows = runtime.jobs(active_only=active_only)
    if not rows:
        context.output("no active jobs" if active_only else "no jobs")
        return
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
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
    output = render_table(
        ("JOB", "SERIAL", "STATE", "PID", "STATUS", "ARTIFACTS", "NAME", "STARTED", "FINISHED", "COMMAND"),
        table_rows,
    )
    if page:
        context.page_text(output)
    else:
        context.output(output)


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
    command = str(row["command_line"])
    line = (
        f"{prefix}#{row['id']} serial={serial} pid={row['pid']} status={row['status']}{name_part}"
        f" launched={format_runtime_timestamp(row['started_at'])}"
        f" finished={format_runtime_timestamp(row['finished_at'])}"
        f" commandlet={commandlet_from_command_line(command)}"
        f" command={command}"
    )
    return f"{line}\n{detail}" if detail else line

def require_job(context: CommandContext, job_id: str | None):
    """Return a job row or raise a user-facing error."""
    runtime = context.runtime_store("job")
    if not job_id:
        raise ValueError("job id is required")
    try:
        numeric_id = int(job_id)
    except ValueError as exc:
        raise ValueError(f"invalid job id: {job_id}") from exc
    row = runtime.job(numeric_id)
    if row is None:
        raise ValueError(f"unknown job: {job_id}")
    return row


def kill_job(context: CommandContext, row) -> None:
    """Forcefully terminate a job process and update its status."""
    runtime = context.runtime_store("job kill")
    pid = row["pid"]
    if pid is None:
        raise ValueError(f"job {row['id']} has no pid")
    try:
        os.kill(int(pid), signal.SIGKILL)
    except ProcessLookupError:
        runtime.finish_job(int(row["id"]), "missing")
        raise ValueError(f"job {row['id']} process is not running") from None
    runtime.finish_job(int(row["id"]), "killed")
    context.output(f"killed job {row['id']}")


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    if context.db is None:
        return []
    return [str(row["id"]) for row in context.db.jobs()]


def cancel_job(context: CommandContext, row) -> None:
    """Request cooperative cancellation for one job row."""
    runtime = context.runtime_store("job cancel")
    context.audit_capability("framework.job.control")
    runtime.request_cancellation("job", str(row["id"]))
    runtime.update_job_status(int(row["id"]), "cancelling")
    context.output(f"cancel requested for job {row['id']}")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Job()
