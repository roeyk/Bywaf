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
from bywaf.plugins.runtime.view_common import filter_runtime_rows_by_events, is_view_command_line, view_selector_candidates
from bywaf.runtime_display import (
    args_from_command_line,
    command_context_style_getter,
    commandlet_from_command_line,
    display_runtime_serial,
    format_command_args,
    format_runtime_duration,
    format_runtime_timestamp,
    parse_runtime_list_selectors,
    render_table,
    runtime_sort_note,
    runtime_sort_key,
    runtime_sort_reverse,
    runtime_state_label,
    runtime_status_summary,
    state_marker,
    terminal_table_width,
)
from bywaf.style import styled_subject_text

ACTIVE_STATUSES = {"queued", "claimed", "running", "pausing", "paused", "cancelling"}
JOB_ACTIONS = ("cancel", "end", "kill")
REMOVED_JOB_ACTIONS = {"list", "show"}
JOB_SORT_KEYS = ("id", "serial", "state", "status", "started", "commandlet")
JobActionHandler = Callable[[CommandContext, Namespace], None]


@commandlet(
    name="job",
    description="Manage background jobs.",
    usage="job [--all] [field=value ...] | job <id> | job <cancel|end|kill> [options] <id>",
    examples=("job", "job --all", "job 1", "job cancel 1", "job end 1", "job kill --hard 1"),
    capabilities=("framework.console.output", "framework.file.page", "framework.job.control"),
)
@argument("action", "job operation", required=False, completion=CompletionSpec("choice", JOB_ACTIONS))
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
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--hard", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("--soft", action="store_true")
        parsed, tokens = parser.parse_known_intermixed_args(args)
        operation = parse_job_operation(tokens)
        parsed.action = operation.action
        parsed.id = operation.id
        parsed.filters = operation.filters
        parsed.sort = operation.sort
        context.require_foreground("job management commands")
        validate_job_mode(parsed.action, soft=parsed.soft, hard=parsed.hard)
        job_action_handlers()[parsed.action](context, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete subcommands and job IDs from the active database."""
        if not args:
            return ["--all", "--page", "sort=", *job_ids(context), *JOB_ACTIONS]
        if len(args) == 1 and args[0] in JOB_ACTIONS:
            return job_ids(context)
        if args and args[-1].startswith("sort="):
            return view_selector_candidates(args[-1], JOB_SORT_KEYS)
        if len(args) == 1:
            candidates = ["--all", "--page", "sort=", *job_ids(context), *JOB_ACTIONS]
            candidates.extend(view_selector_candidates(prefix, JOB_SORT_KEYS))
            return [candidate for candidate in candidates if candidate.startswith(prefix)]
        if len(args) >= 2 and args[0] in JOB_ACTIONS:
            return job_ids(context)
        return []


def parse_job_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `job` forms into the internal action/id/filter shape."""
    if not tokens:
        return Namespace(action="list", id=None, filters={}, sort="")
    first, rest = tokens[0], tokens[1:]
    if first in REMOVED_JOB_ACTIONS:
        raise ValueError("usage: job [--all] [field=value ...] | job <id> | job <cancel|end|kill> [options] <id>")
    if first in JOB_ACTIONS:
        if not rest:
            raise ValueError(f"job {first} requires a job id")
        filters, sort = parse_runtime_list_selectors(rest[1:], allowed_sort_keys=JOB_SORT_KEYS, command="job")
        return Namespace(action=first, id=rest[0], filters=filters, sort=sort)
    if first.startswith("serial=") and not rest:
        return Namespace(action="show", id=first.split("=", 1)[1], filters={}, sort="")
    if "=" not in first and not rest:
        return Namespace(action="show", id=first, filters={}, sort="")
    filters, sort = parse_runtime_list_selectors(tokens, allowed_sort_keys=JOB_SORT_KEYS, command="job")
    return Namespace(action="list", id=None, filters=filters, sort=sort)


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
    print_jobs(
        context,
        active_only=False,
        show_active=parsed.all,
        page=parsed.page,
        filters=parsed.filters,
        sort_key=parsed.sort,
    )


def show_job_action(context: CommandContext, parsed: Namespace) -> None:
    """Run `job show`."""
    row = require_job(context, parsed.id)
    display_name = context.runtime_store("job show").runtime_names().get(("job", str(row["id"])))
    context.output(
        format_job(
            row,
            display_name=display_name,
            args=latest_job_args(context, row["id"]),
            style_getter=command_context_style_getter(context),
        )
    )


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


def print_jobs(
    context: CommandContext,
    *,
    active_only: bool = True,
    show_active: bool = False,
    page: bool = False,
    filters: dict[str, str] | None = None,
    sort_key: str = "",
) -> None:
    """Print known jobs with newest first."""
    runtime = context.runtime_store("job list")
    rows = runtime.jobs(active_only=active_only)
    rows = [row for row in rows if not is_view_command_line(str(row["command_line"]))]
    if filters:
        events = context.event_store("job list")
        rows = filter_runtime_rows_by_events(events, "job", rows, filters)
    if sort_key:
        rows = sort_job_rows(rows, sort_key)
    if not rows:
        context.output("no matching jobs" if filters else "no active jobs" if active_only else "no jobs")
        return
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
    table_rows: list[tuple[object, ...]] = []
    row_subjects: list[str] = []
    for row in rows:
        # Listings keep time in STARTED/DUR only. Detail views can carry richer
        # lifecycle prose without duplicating timestamps across table cells.
        state = runtime_state_label(row["status"])
        table_rows.append(
            (
                row["id"],
                runtime_status_summary(row["status"]),
                format_runtime_timestamp(row["started_at"]),
                format_runtime_duration(row["started_at"], row["finished_at"]),
                artifact_counts.get(str(row["id"]), 0),
                names.get(("job", str(row["id"])), ""),
                format_job_command(str(row["command_line"])),
            )
        )
        row_subjects.append("table.active_row" if state in {"active", "in progress"} else "")
    output = render_table(
        ("JOB", "STATUS", "STARTED", "DUR", "ART", "NAME", "COMMAND"),
        table_rows,
        cell_subjects=("job", "", "timestamp", "timestamp", "", "", "command_line"),
        row_subjects=row_subjects,
        active_column_indexes=(1,),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    if sort_key:
        output = f"{runtime_sort_note(sort_key)}\n{output}"
    if page:
        context.page_text(output)
    else:
        context.output(output)


def sort_job_rows(rows: list[dict], sort_key: str) -> list[dict]:
    """Return job rows ordered by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    sorters = {
        "id": lambda row: int(row["id"]),
        "serial": lambda row: str(row["serial"]),
        "state": lambda row: runtime_state_label(row["status"]),
        "status": lambda row: str(row["status"]),
        "started": lambda row: str(row["started_at"] or ""),
        "commandlet": lambda row: commandlet_from_command_line(str(row["command_line"])),
    }
    return sorted(rows, key=sorters[display_key], reverse=runtime_sort_reverse(sort_key))


def format_job_command(command_line: str) -> str:
    """Return commandlet plus arguments as one compact table cell."""
    commandlet = commandlet_from_command_line(command_line)
    args = format_command_args(args_from_command_line(command_line))
    return f"{commandlet} {args}".strip()


def validate_job_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for job management operations."""
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("job cancel is already cooperative; use job end --hard or job kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"job {action} does not accept --soft or --hard")


def format_job(
    row,
    *,
    display_name: str | None = None,
    show_active: bool = False,
    marker_style: str = "short",
    args: list[str] | None = None,
    style_getter=None,
) -> str:
    """Format one job as a readable detail block."""
    prefix = ""
    detail = ""
    if show_active:
        label = runtime_state_label(row["status"])
        timestamp = row["started_at"] if label in {"active", "in progress"} else row["finished_at"]
        prefix, detail = state_marker(label, timestamp, style=marker_style)
    job_id = styled_subject_text(style_getter, "job", row["id"]) if style_getter else row["id"]
    serial = display_runtime_serial(row["serial"])
    serial = styled_subject_text(style_getter, "serial", serial) if style_getter else serial
    command = str(row["command_line"])
    commandlet = commandlet_from_command_line(command)
    displayed_args = args or list(args_from_command_line(command))
    displayed_command = f"{commandlet} {format_command_args(displayed_args)}".strip() if displayed_args else command
    displayed_command = styled_subject_text(style_getter, "command_line", displayed_command) if style_getter else displayed_command
    lines = [
        f"  job: {prefix}{job_id}",
        f"  serial: {serial}",
        f"  pid: {row['pid']}",
        f"  status: {row['status']}",
        f"  launched: {format_runtime_timestamp(row['started_at'])}",
        f"  finished: {format_runtime_timestamp(row['finished_at'])}",
        f"  duration: {format_runtime_duration(row['started_at'], row['finished_at'])}",
        f"  command line: {displayed_command}",
    ]
    if display_name:
        lines.insert(3, f"  name: {display_name}")
    block = "Job summary\n" + "\n".join(lines)
    return f"{block}\n\n{detail}" if detail else block


def latest_job_args(context: CommandContext, job_id: int | str) -> list[str]:
    """Return the newest recorded commandlet arguments for a job, if present."""
    events = context.event_store("job show arguments").events_for_job(int(job_id), limit=10000)
    argument_events = [event for event in events if event.topic == "command.run.arguments"]
    if not argument_events:
        return []
    payload_args = max(argument_events, key=lambda event: event.id or 0).payload.get("args")
    if isinstance(payload_args, list):
        return [str(arg) for arg in payload_args]
    return []


def require_job(context: CommandContext, job_id: str | None):
    """Return a job row or raise a user-facing error."""
    runtime = context.runtime_store("job")
    if not job_id:
        raise ValueError("job id is required")
    try:
        numeric_id = int(job_id)
    except ValueError:
        resolved = runtime.job_id_for_serial(job_id)
        if resolved is None:
            raise ValueError(f"unknown job: {job_id}") from None
        numeric_id = int(resolved)
    row = runtime.job(numeric_id)
    if row is None and job_id.isdigit():
        resolved = runtime.job_id_for_serial(job_id)
        if resolved is not None:
            row = runtime.job(int(resolved))
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
        # Hard kill is intentionally separate from cooperative cancellation; it
        # is the operator's escape hatch when a child process ignores requests.
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
