"""Runtime object display helpers.

Provides job, step, and summary renderers for runtime state shown from the REPL.

Used by:
- repl.commands: implement `info` and legacy runtime display helpers.
- tests: verify runtime listings and selectors remain readable."""

from __future__ import annotations

from ...event.filters import any_event_matches_filters
from ...runtime_display import (
    ACTIVE_LISTING_FORMAT_VAR,
    args_from_command_line,
    commandlet_from_command_line,
    display_runtime_serial,
    format_command_args,
    format_runtime_duration,
    format_runtime_timestamp,
    normalize_active_listing_format,
    render_table,
    runtime_state_label,
    runtime_state_text,
)
from ...runner import Runner
from .variables import subject_text

def print_jobs(runner: Runner) -> None:
    """Print known background jobs."""
    runtime = runner.runtime
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
    rows = [
        (
            row["id"],
            display_runtime_serial(row["serial"]),
            row["pid"],
            row["status"],
            artifact_counts.get(str(row["id"]), 0),
            names.get(("job", str(row["id"])), ""),
            format_runtime_timestamp(row["started_at"]),
            format_runtime_duration(row["started_at"], row["finished_at"]),
            commandlet_from_command_line(str(row["command_line"])),
            format_command_args(args_from_command_line(str(row["command_line"]))),
        )
        for row in runtime.jobs()
    ]
    if rows:
        print(
            render_table(
                ("JOB", "SERIAL", "PID", "STATUS", "ARTIFACTS", "NAME", "STARTED", "DURATION", "COMMANDLET", "ARGS"),
                rows,
                cell_subjects=("job", "serial", "", "", "", "", "timestamp", "timestamp", "command_line", "command_line"),
                style_getter=runner.registry.varstore.get,
            )
        )


def print_info(runner: Runner) -> None:
    """Print a compact runtime dashboard for entities currently in play."""
    runtime = runner.runtime
    print(f"Jobs ({len(runtime.jobs(active_only=True))})")
    # Reuse runtime commandlets so `info` does not maintain
    # a separate table format from the primary commands.
    process_events_for_info(runner, run_info_commandlet(runner, "job"))
    print()
    print(f"Pipelines ({len(runtime.pipelines(active_only=True))})")
    process_events_for_info(runner, run_info_commandlet(runner, "pipeline"))
    print()
    print(f"Steps ({len(runtime.runs(active_only=True))})")
    process_events_for_info(runner, run_info_commandlet(runner, "step"))


def run_info_commandlet(runner: Runner, command: str):
    """Run one info sub-commandlet and return events it emitted."""
    after_id = runner.events.latest_event_id()
    runner.execute(command)
    return runner.events.events_matching(after_id=after_id, limit=1000)


def process_events_for_info(runner: Runner, events) -> None:
    """Print framework output events emitted by commandlets during `info`."""
    del runner
    for event in events:
        if event.topic == "framework.console.output.requested":
            print(event.payload.get("text", ""), end=event.payload.get("end", "\n"))


def print_runs(runner: Runner, *, active_only: bool = True, filters: dict[str, str] | None = None) -> None:
    """Print commandlet step summaries."""
    runtime = runner.runtime
    rows = runtime.runs(active_only=active_only)
    if filters:
        rows = [
            row
            for row in rows
            if any_event_matches_filters(
                runner.events.events_matching(command_run_id=str(row["command_run_id"]), limit=10000),
                filters,
            )
        ]
    if not rows:
        print("no matching steps" if filters else "no active steps" if active_only else "no steps")
        return
    marker_style = normalize_active_listing_format(
        runner.registry.varstore.get(f"global.{ACTIVE_LISTING_FORMAT_VAR}")
    )
    names = runtime.runtime_names()
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_run()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        run_serial = str(row["command_run_id"])
        pipeline_serial = str(row["pipeline_id"]) if row["pipeline_id"] is not None else ""
        pipeline_alias = pipeline_aliases.get(pipeline_serial, "")
        label = runtime_state_label(row["job_statuses"])
        # Active rows are more useful with their first event time; completed
        # rows are more useful with the latest event/finish time.
        timestamp = row["first_event"] if label in {"active", "in progress"} else row["last_event"]
        table_rows.append(
            (
                run_aliases.get(run_serial, run_serial),
                display_runtime_serial(run_serial),
                runtime_state_text(row["job_statuses"], timestamp, style=marker_style),
                names.get(("run", run_serial), ""),
                pipeline_alias,
                display_runtime_serial(pipeline_serial),
                row["source"],
                row["events"],
                artifact_counts.get(run_serial, 0),
                format_runtime_timestamp(row["first_event"]),
                format_runtime_duration(row["first_event"], row["last_event"]),
            )
        )
    print(
        render_table(
            ("STEP", "SERIAL", "STATE", "NAME", "PIPELINE", "PIPELINE_SERIAL", "SOURCE", "EVENTS", "ARTIFACTS", "FIRST_SEEN", "DURATION"),
            table_rows,
            cell_subjects=("step", "serial", "", "", "pipeline", "serial", "", "", "", "timestamp", "timestamp"),
            style_getter=runner.registry.varstore.get,
        )
    )


def print_job(runner: Runner, job_id: str) -> None:
    """Print one job row by ID."""
    runtime = runner.runtime
    names = runtime.runtime_names()
    for row in runtime.jobs():
        if str(row["id"]) == job_id:
            args = format_command_args(args_from_command_line(str(row["command_line"])))
            args_part = f" args={args}" if args else ""
            print(
                f"#{subject_text(runner, 'job', row['id'])} serial={subject_text(runner, 'serial', row['serial'])}"
                f" pid={row['pid']} status={row['status']}"
                f"{format_runtime_name(names.get(('job', str(row['id']))))}"
                f" launched={format_runtime_timestamp(row['started_at'])}"
                f" finished={format_runtime_timestamp(row['finished_at'])}"
                f" commandlet={commandlet_from_command_line(str(row['command_line']))}"
                f"{args_part}"
            )
            return
    print(f"error: unknown job: {job_id}")


def format_runtime_name(display_name: str | None) -> str:
    """Return a compact runtime name fragment for listings."""
    return f" name={display_name}" if display_name else ""
