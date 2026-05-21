"""Display helpers for the interactive shell."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .plugin import CommandContext
from .rendering import Column, Table, render_console_table
from .runtime_display import (
    ACTIVE_LISTING_FORMAT_VAR,
    display_runtime_serial,
    format_runtime_timestamp,
    normalize_active_listing_format,
    render_table,
    runtime_state_label,
    runtime_state_text,
)
from .runner import Runner
from .secrets import SECRET_REF_PREFIX, REDACTED_VALUE


@dataclass(frozen=True, slots=True)
class HelpEntry:
    """Help text for REPL built-ins that are not backed by commandlets."""

    command: str
    description: str
    usage: str
    examples: tuple[str, ...] = ()
    summary: str = ""


HELP_COMMANDS = (
    HelpEntry("help, ?", "show this help", "help [command]"),
    HelpEntry("plugins", "list loaded plugin providers", "plugins"),
    HelpEntry("cmds", "show commandlets grouped by plugin provider", "cmds"),
    HelpEntry("triggers", "show provider-owned trigger rules", "triggers"),
    HelpEntry("history", "show command history", "history"),
    HelpEntry("info", "show active jobs, pipelines, and runs", "info"),
    HelpEntry("jobs", "alias for job list", "jobs"),
    HelpEntry("pipelines", "alias for pipeline list", "pipelines"),
    HelpEntry("runs", "show commandlet run IDs", "runs"),
    HelpEntry("vars [name[=value]]", "list, show, or set session variables", "vars [name[=value]]", ("vars http_probe.cookie-file=/tmp/cookies.txt", "vars http_probe.cookie-file")),
    HelpEntry("topics", "list event topics in the active database", "topics"),
    HelpEntry("project", "list, inspect, create, or switch project directories", "project <list|info|new|use>"),
    HelpEntry("use <commandlet|global>", "set the active variable context", "use <commandlet|global>"),
    HelpEntry("event", "show events for a topic, job, run, pipeline, or serial", "event <topic|job=id|run=id|pipeline=id|serial=id>", ("event host.found", "event run=1", "event pipeline=1", "event serial=hostscanner-..."), "event <selector>"),
    HelpEntry("events [tail|--tail] [last=N]", "show recent events", "events [tail|--tail] [last=N]", ("events", "events tail", "events tail last=50")),
    HelpEntry("prompt [pattern]", "show or set prompt pattern", "prompt [pattern]", ("prompt %u@%h %T > ",)),
    HelpEntry("load [--force] plugin=<path>", "load a filesystem plugin", "load [--force] plugin=<path>"),
    HelpEntry("load script=<path>", "run commands from a script file", "load script=<path>"),
    HelpEntry("load db=<path>", "switch active SQLite database", "load db=<path>"),
    HelpEntry("load config=<path>", "load session variables from JSON", "load config=<path>"),
    HelpEntry("load history=<path>", "load command history for this session", "load history=<path>"),
    HelpEntry("save [--encrypt] db=<path>", "save active SQLite database", "save [--encrypt] db=<path>"),
    HelpEntry("save config=<path>", "save session variables to JSON", "save config=<path>"),
    HelpEntry("save history=<path>", "save this session's command history", "save history=<path>"),
    HelpEntry("run <pipeline>", "run a commandlet pipeline", "run <pipeline>", ("run 'hostscanner 127.0.0.1 | portscanner'",)),
    HelpEntry("<plugin pipeline>", "run commandlets directly", "<plugin pipeline>", ("hostscanner 127.0.0.1 | portscanner",)),
    HelpEntry("exit, quit, q", "exit the shell", "exit"),
)


def format_event(event) -> str:
    """Render one event row for human-readable console output."""

    return f"#{event.id} {event.topic} {event.payload}"


def friendly_error(exc: Exception) -> str:
    """Normalize exception text for REPL display."""
    if isinstance(exc, KeyError):
        return str(exc).strip("'")
    return str(exc)


def print_events(events) -> None:
    """Print persisted events in a compact inspectable form."""
    for event in events:
        print(format_event(event))


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a command run."""
    rows = runner.runtime.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(f"  {row['name']}={display_var_value(runner, row['value'])}")


def print_history(entries: Sequence[str] = (), selectors: dict[str, str] | None = None) -> None:
    """Print the current session history, optionally filtered by time bounds."""
    window = history_time_window(selectors or {})
    for entry in entries:
        if history_entry_in_window(entry, window):
            print(format_history_entry_for_display(entry))


def format_history_entry_for_display(entry: str) -> str:
    """Display script-friendly history as timestamp-first for readability."""
    command, separator, timestamp = entry.rpartition("  # ")
    if not separator or not timestamp:
        return entry
    return f"{timestamp}  {command}"


def history_time_window(selectors: dict[str, str]) -> tuple[str | None, str | None]:
    """Convert history selectors to inclusive compact timestamp bounds."""
    since = normalize_history_time_bound(selectors["since"], until=False) if "since" in selectors else None
    until = normalize_history_time_bound(selectors["until"], until=True) if "until" in selectors else None
    return since, until


def normalize_history_time_bound(value: str, *, until: bool) -> str:
    """Normalize `yyyymmdd[HH[MM[SS]]]` or `time:<...>` to YYYYMMDDHHMMSS."""
    if ":" in value:
        kind, raw = value.split(":", 1)
        if kind != "time":
            raise ValueError("history since=/until= only supports time bounds")
    else:
        raw = value
    digits = "".join(char for char in raw if char.isdigit())
    if len(digits) not in {8, 10, 12, 14}:
        raise ValueError("history time must be yyyymmdd[HH[MM[SS]]]")
    if len(digits) == 8:
        return digits + ("235959" if until else "000000")
    if len(digits) == 10:
        return digits + ("5959" if until else "0000")
    if len(digits) == 12:
        return digits + ("59" if until else "00")
    return digits


def history_entry_in_window(entry: str, window: tuple[str | None, str | None]) -> bool:
    """Return whether a script-friendly history entry falls within a time window."""
    since, until = window
    _command, separator, timestamp = entry.rpartition("  # ")
    if not separator:
        return since is None and until is None
    compact = "".join(char for char in timestamp if char.isdigit())
    if len(compact) < 14:
        return since is None and until is None
    compact = compact[:14]
    return (since is None or compact >= since) and (until is None or compact <= until)


def print_help(runner: Runner, command: str | None = None) -> None:
    """Print built-in help or delegate commandlet help."""
    if command:
        print_command_help(runner, command)
        return
    width = max(len(entry.summary or entry.command) for entry in HELP_COMMANDS)
    for entry in HELP_COMMANDS:
        command = entry.summary or entry.command
        print(f"{command:<{width}}  {entry.description}")


def print_command_help(runner: Runner, command: str) -> None:
    """Show help for either a plugin commandlet or shell built-in."""
    plugin = runner.registry.plugins.get(command)
    if plugin:
        print_plugin_argparse_help(runner, plugin)
        return
    entry = find_help_entry(command)
    if entry:
        print_help_entry(entry)
        return
    print(f"error: unknown command: {command}")


def find_help_entry(command: str) -> HelpEntry | None:
    """Find built-in help by command name or alias."""
    for entry in HELP_COMMANDS:
        aliases = [part.strip().split()[0] for part in entry.command.split(",")]
        if command in aliases:
            return entry
    return None


def print_help_entry(entry: HelpEntry) -> None:
    """Render one built-in help entry."""
    print(f"Command: {entry.command}")
    print(f"Usage:   {entry.usage}")
    if entry.examples:
        print("Examples:")
        for example in entry.examples:
            print(f"  {example}")
    print()
    print(entry.description)


def print_plugin_argparse_help(runner: Runner, plugin) -> None:
    """Ask a commandlet's argparse parser to print its native help."""
    context = CommandContext(
        runner.db,
        source=plugin.spec.name,
        _varstore=runner.registry.varstore,
        _secrets=runner.registry.secrets,
    )
    try:
        list(plugin.run(context, ["--help"], []))
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


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
            format_runtime_timestamp(row["finished_at"]),
            row["command_line"],
        )
        for row in runtime.jobs()
    ]
    if rows:
        print(render_table(("JOB", "SERIAL", "PID", "STATUS", "ARTIFACTS", "NAME", "STARTED", "FINISHED", "COMMAND"), rows))


def print_info(runner: Runner) -> None:
    """Print a compact runtime dashboard for entities currently in play."""
    runtime = runner.runtime
    print(f"Jobs ({len(runtime.jobs(active_only=True))})")
    events = runner.execute("job list")
    process_events_for_non_repl_info(runner, events)
    print()
    print(f"Pipelines ({len(runtime.pipelines(active_only=True))})")
    events = runner.execute("pipeline list")
    process_events_for_non_repl_info(runner, events)
    print()
    print(f"Runs ({len(runtime.runs(active_only=True))})")
    print_runs(runner)


def process_events_for_non_repl_info(runner: Runner, events) -> None:
    """Print framework output events emitted by commandlets during `info`."""
    del runner
    for event in events:
        if event.topic == "framework.console.output.requested":
            print(event.payload.get("text", ""), end=event.payload.get("end", "\n"))


def print_runs(runner: Runner, *, active_only: bool = True) -> None:
    """Print command run summaries."""
    runtime = runner.runtime
    rows = runtime.runs(active_only=active_only)
    if not rows:
        print("no active runs" if active_only else "no runs")
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
                format_runtime_timestamp(row["last_event"]),
            )
        )
    print(
        render_table(
            ("RUN", "SERIAL", "STATE", "NAME", "PIPELINE", "PIPELINE_SERIAL", "SOURCE", "EVENTS", "ARTIFACTS", "FIRST", "LAST"),
            table_rows,
        )
    )


def print_job(runner: Runner, job_id: str) -> None:
    """Print one job row by ID."""
    runtime = runner.runtime
    names = runtime.runtime_names()
    for row in runtime.jobs():
        if str(row["id"]) == job_id:
            print(
                f"#{row['id']} serial={row['serial']} pid={row['pid']} status={row['status']}"
                f"{format_runtime_name(names.get(('job', str(row['id']))))} {row['command_line']}"
            )
            return
    print(f"error: unknown job: {job_id}")


def format_runtime_name(display_name: str | None) -> str:
    """Return a compact runtime name fragment for listings."""
    return f" name={display_name}" if display_name else ""


def display_var_value(runner: Runner, value: str) -> str:
    """Return a variable value with in-memory secret references redacted."""
    secret_ref = runner.registry.secrets.metadata(value)
    if secret_ref is None:
        if value.startswith(SECRET_REF_PREFIX):
            return f"{REDACTED_VALUE} fingerprint=unavailable"
        return value
    return f"{REDACTED_VALUE} fingerprint={secret_ref.fingerprint.format()}"


def print_topics(runner: Runner, prefix: str = "") -> None:
    """Print event topics known to the active database, optionally filtered."""
    matched = [topic for topic in runner.events.topics() if topic.startswith(prefix)]
    for topic in matched:
        print(topic)
    if prefix and not matched:
        print(f"no matching topics: {prefix}")


def print_commandlets(runner: Runner, *, page: bool = False) -> None:
    """Print commandlets grouped under their plugin providers."""
    lines = render_commandlets(runner)
    if page:
        page_generated_text("\n".join(lines))
        return
    print("\n".join(lines))


def print_triggers(runner: Runner) -> None:
    """Print provider-owned trigger rules."""
    if not runner.registry.triggers:
        print("no triggers loaded")
        return
    states = {str(row["name"]): row for row in runner.db.trigger_states()}
    rows = []
    for trigger in sorted(runner.registry.triggers, key=lambda item: runner.registry.trigger_id(item)):
        trigger_id = runner.registry.trigger_id(trigger)
        state = states.get(trigger_id)
        rows.append(
            {
                "provider": runner.registry.trigger_provider(trigger) or "",
                "name": trigger.name,
                "topic": trigger.topic,
                "action": trigger.action_command,
                "mode": trigger.action_mode,
                "cursor": str(state["last_event_id"]) if state is not None else "0",
            }
        )
    print(
        render_console_table(
            Table(
                (
                    Column("provider", "PROVIDER"),
                    Column("name", "TRIGGER"),
                    Column("topic", "TOPIC"),
                    Column("action", "ACTION"),
                    Column("mode", "MODE"),
                    Column("cursor", "CURSOR"),
                ),
                tuple(rows),
            )
        )
    )


def render_commandlets(runner: Runner) -> list[str]:
    """Return commandlets grouped under their plugin providers."""
    lines: list[str] = []
    for provider, commandlets in runner.registry.grouped_names().items():
        lines.append(provider)
        for commandlet in commandlets:
            lines.append(f"  {commandlet}")
    return lines


def page_generated_text(text: str) -> None:
    """Page built-in generated text through the system pager when available."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write(text)
        if text and not text.endswith("\n"):
            handle.write("\n")
        path = Path(handle.name)
    try:
        pager = shutil.which("less")
        if pager and sys.stdin.isatty() and sys.stdout.isatty():
            subprocess.run([pager, str(path)], check=False)
            return
        print(path.read_text(errors="replace"), end="", flush=True)
    finally:
        path.unlink(missing_ok=True)
