"""Interactive shell and framework request handling."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import shlex
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .completion import Completer, build_prompt_session, install_readline
from .framework_requests import process_framework_requests
from .nmap_backend import NmapScanError, NmapUnavailableError
from .plugin import CommandContext
from .projects import ProjectPaths
from .registry import PluginTrustError
from .rendering import Column, Table, render_console_table
from .repl_resources import (
    DEFAULT_HISTORY,
    dispatch_project_command,
    load_repl_resource,
    print_project_info,
    save_repl_resource,
)
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
from .secrets import SECRET_REF_PREFIX, REDACTED_VALUE, is_secret_name, load_or_create_fingerprint_key, redact_command_text
from .triggers import disable_session_triggers, start_default_services, stop_session_services


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

DEFAULT_HISTORY_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S %Z"
HISTORY_TIMESTAMP_FORMAT_VAR = "history.timestamp-format"


@dataclass(slots=True)
class ShellState:
    """Mutable REPL-only state that should not live in the database."""

    prompt_pattern: str = "bywaf> "
    history_path: Path = field(default_factory=lambda: DEFAULT_HISTORY)
    session_history: list[str] = field(default_factory=list)
    handled_request_ids: set[int] = field(default_factory=set)
    framework_request_after_id: int = 0
    active_context: str | None = None
    completer: Completer | None = None

    def prompt(self) -> str:
        return render_prompt(self.prompt_pattern)



def format_event(event) -> str:
    """Render one event row for human-readable console output."""

    return f"#{event.id} {event.topic} {event.payload}"


def shutdown_runner(runner: Runner) -> None:
    """Flush SQLite WAL state before the process exits."""

    stop_session_services(runner)
    disable_session_triggers(runner)
    runner.maintenance.checkpoint()


def repl(runner: Runner) -> None:
    """Run the interactive shell until EOF, interrupt, or an exit command."""

    state = new_shell_state(runner)
    state.completer = Completer(runner.registry, runner.db)
    input_reader = build_input_reader(state.completer)
    start_default_services(runner)
    try:
        while True:
            process_framework_requests(runner, state)
            start_default_services(runner)
            try:
                line = read_logical_input(state, input_reader).strip()
            except EOFError:
                print()
                return
            except KeyboardInterrupt:
                print()
                if confirm_repl_exit(input_reader):
                    return
                continue
            record_command_history(
                line,
                state.history_path,
                state.session_history,
                runner.registry.varstore.get(
                    HISTORY_TIMESTAMP_FORMAT_VAR,
                    DEFAULT_HISTORY_TIMESTAMP_FORMAT,
                ) or DEFAULT_HISTORY_TIMESTAMP_FORMAT,
                stored_command=redact_history_command(line),
            )
            if dispatch_repl_line(runner, line, state) == "exit":
                return
            process_framework_requests(runner, state)
    finally:
        shutdown_runner(runner)


def build_input_reader(completer: Completer) -> Callable[[str], str]:
    """Return the best available line reader for the current terminal."""
    if os.environ.get("BYWAF_INPUT_READER", "").casefold() != "readline" and sys.stdin.isatty() and sys.stdout.isatty():
        session = build_prompt_session(completer)
        if session is not None:
            return session.prompt
    install_readline(completer)
    return input


def confirm_repl_exit(reader: Callable[[str], str]) -> bool:
    """Ask whether Ctrl-C should exit the REPL."""
    while True:
        try:
            answer = reader("Quit Bywaf? [y/N] ").strip().lower()
        except KeyboardInterrupt:
            print()
            return False
        except EOFError:
            print()
            return True
        if answer in {"", "n", "no"}:
            return False
        if answer in {"y", "yes"}:
            return True
        print("please answer yes or no")


def read_logical_input(state: ShellState, reader: Callable[[str], str] | None = None) -> str:
    """Read one logical REPL command, joining backslash continuations."""
    reader = reader or input
    lines: list[str] = []
    prompt = state.prompt()
    while True:
        line = reader(prompt)
        if line_has_continuation(line):
            lines.append(remove_line_continuation(line))
            prompt = "... "
            continue
        lines.append(line)
        return "\n".join(lines)


def dispatch_repl_line(runner: Runner, line: str, state: ShellState | None = None) -> str | None:
    """Dispatch one REPL line and keep errors user-facing.

    Built-ins are handled here; commandlets fall through to the generic runner
    so plugin commands such as `ls` are not hard-coded into the shell.
    """
    state = state or ShellState(framework_request_after_id=runner.events.latest_event_id())
    commands = split_command_sequence(line)
    if len(commands) > 1:
        for command in commands:
            if dispatch_repl_line(runner, command, state) == "exit":
                return "exit"
        return None
    try:
        parts = line.split(maxsplit=1)
        if not parts:
            return None
        name = parts[0]
        rest = parts[1] if len(parts) > 1 else None
        handler = REPL_COMMAND_HANDLERS.get(name)
        if handler is not None:
            return handler(runner, state, rest, line)
        if name in runner.registry.plugins:
            execute_repl_commandlet(runner, state, line)
            return None
        print(f"error: unknown command or commandlet: {name}")
    except SystemExit as exc:
        if exc.code not in (0, None):
            print(f"error: command failed with exit code {exc.code}")
    except (NmapUnavailableError, NmapScanError) as exc:
        print(f"error: {exc}")
    except PluginTrustError as exc:
        print(str(exc))
    except (KeyError, ValueError) as exc:
        print(f"error: {friendly_error(exc)}")
    except Exception as exc:
        print(f"error: {exc}")
    return None


ReplCommandHandler = Callable[[Runner, ShellState, str | None, str], str | None]


def handle_exit_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Exit the REPL."""
    del runner, state, rest, line
    return "exit"


def handle_help_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print general or command-specific help."""
    del state, line
    print_help(runner, rest)
    return None


def handle_plugins_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print loaded plugin providers."""
    del state, rest, line
    print("\n".join(runner.registry.provider_names()))
    return None


def handle_cmds_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print commandlets, optionally through the pager."""
    del state, line
    print_commandlets(runner, page=rest == "--page")
    return None


def handle_triggers_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print trigger rules."""
    del state, rest, line
    print_triggers(runner)
    return None


def handle_history_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print command history."""
    del runner, line
    selectors = parse_history_selectors(shlex.split(rest)) if rest else None
    print_history(state.session_history, selectors)
    return None


def handle_info_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print runtime overview."""
    del state, rest, line
    print_info(runner)
    return None


def handle_jobs_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run the job-list commandlet shortcut."""
    del line
    suffix = f" {rest}" if rest in {"--all", "--page"} else ""
    events = runner.execute(f"job list{suffix}")
    process_framework_requests(runner, state)
    print_events(events)
    return None


def handle_pipelines_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run the pipeline-list commandlet shortcut."""
    del line
    suffix = " --page" if rest == "--page" else ""
    events = runner.execute(f"pipeline list{suffix}")
    process_framework_requests(runner, state)
    print_events(events)
    return None


def handle_runs_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print commandlet runs."""
    del state, line
    print_runs(runner, active_only=rest != "--all")
    return None


def handle_use_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the active variable context."""
    del line
    if rest is None:
        print(state.active_context or "global")
    else:
        set_active_context(runner, state, rest)
    return None


def handle_vars_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """List, show, or set variables."""
    del line
    if rest is None:
        print_vars(runner, state)
    elif "=" in rest:
        set_var(runner, state, rest)
    else:
        print_var(runner, state, rest)
    return None


def handle_topics_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print event topics."""
    del state, line
    print_topics(runner, rest or "")
    return None


def handle_project_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or dispatch project commands."""
    del line
    if rest is None:
        print_project_info(runner)
    else:
        dispatch_project_command(runner, state, shlex.split(rest))
    return None


def handle_event_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print matching events."""
    del state, line
    if rest is None:
        print("usage: event <topic>")
    elif rest.startswith("job="):
        print_job(runner, rest.split("=", 1)[1])
    elif rest.startswith("run="):
        run_id = runner.runtime.resolve_run_serial(rest.split("=", 1)[1])
        print_run_variables(runner, run_id)
        print_events(runner.events.events_matching(command_run_id=run_id))
    elif rest.startswith("pipeline="):
        pipeline_id = runner.runtime.resolve_pipeline_serial(rest.split("=", 1)[1])
        print_events(runner.events.events_matching(pipeline_id=pipeline_id))
    elif rest.startswith("serial="):
        print_events(runner.events.events_for_serial(rest.split("=", 1)[1]))
    elif rest.startswith("topic="):
        print_events(runner.events.events_matching(topic=rest.split("=", 1)[1]))
    else:
        print_events(runner.events.events_for_topic(rest))
    return None


def handle_events_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print recent events."""
    del state, line
    limit = parse_events_selectors(shlex.split(rest)) if rest else 25
    print_events(runner.events.recent_events(limit))
    return None


def handle_prompt_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the prompt pattern."""
    del line
    if rest is None:
        print(state.prompt_pattern)
    else:
        set_prompt_pattern(runner, state, rest, source="user")
    return None


def handle_load_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load a REPL resource."""
    del line
    if rest is not None:
        load_repl_resource(runner, rest, state)
    return None


def handle_save_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Save a REPL resource."""
    del line
    if rest is None:
        print("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
    else:
        save_repl_resource(runner, rest, state)
    return None


def handle_run_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Run a commandlet pipeline."""
    del line
    if rest is not None:
        execute_repl_commandlet(runner, state, rest)
    return None


def execute_repl_commandlet(runner: Runner, state: ShellState, command: str) -> None:
    """Run a commandlet line and print emitted events."""
    events = runner.execute(command)
    process_framework_requests(runner, state)
    print_events(events)


REPL_COMMAND_HANDLERS: dict[str, ReplCommandHandler] = {
    "?": handle_help_command,
    "cmds": handle_cmds_command,
    "event": handle_event_command,
    "events": handle_events_command,
    "exit": handle_exit_command,
    "help": handle_help_command,
    "history": handle_history_command,
    "info": handle_info_command,
    "jobs": handle_jobs_command,
    "load": handle_load_command,
    "pipelines": handle_pipelines_command,
    "plugins": handle_plugins_command,
    "project": handle_project_command,
    "prompt": handle_prompt_command,
    "q": handle_exit_command,
    "quit": handle_exit_command,
    "run": handle_run_command,
    "runs": handle_runs_command,
    "save": handle_save_command,
    "topics": handle_topics_command,
    "triggers": handle_triggers_command,
    "use": handle_use_command,
    "vars": handle_vars_command,
}



def set_prompt_pattern(runner: Runner, state: ShellState, pattern: str, *, source: str) -> None:
    """Set the REPL prompt and record the change as an auditable event."""
    old_prompt = state.prompt_pattern
    state.prompt_pattern = pattern
    runner.events.publish(
        "shell.prompt.updated",
        {"old_prompt": old_prompt, "new_prompt": pattern, "source": source},
        "framework",
    )


def new_shell_state(runner: Runner) -> ShellState:
    """Create shell state that ignores historical framework requests."""
    project = runner.project if isinstance(runner.project, ProjectPaths) else None
    history_path = project.history if project is not None else DEFAULT_HISTORY
    return ShellState(
        framework_request_after_id=runner.events.latest_event_id(),
        history_path=history_path,
    )


def friendly_error(exc: Exception) -> str:
    """Normalize exception text for REPL display."""
    if isinstance(exc, KeyError):
        return str(exc).strip("'")
    return str(exc)


def print_events(events) -> None:
    """Print persisted events in a compact inspectable form."""
    for event in events:
        print(format_event(event))


def parse_events_selectors(selectors: Sequence[str]) -> int:
    """Parse `events [tail|--tail] [last=N]` and return the requested tail size."""
    limit = 25
    seen_last = False
    for selector in selectors:
        if selector in {"tail", "--tail"}:
            continue
        if selector.startswith("last="):
            if seen_last:
                raise ValueError("events last= may only be provided once")
            seen_last = True
            limit = parse_events_last_value(selector.split("=", 1)[1])
            continue
        raise ValueError("usage: events [tail|--tail] [last=N]")
    return limit


def parse_events_last_value(raw: str) -> int:
    """Parse a positive integer event tail size."""
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid events last= value: {raw}") from exc
    if limit < 1:
        raise ValueError("events last= must be at least 1")
    return limit


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


def parse_history_selectors(tokens: Sequence[str]) -> dict[str, str]:
    """Parse `history since=... until=...` selector tokens."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        key, value = token.split("=", 1)
        if key not in {"since", "until"}:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        if not value:
            raise ValueError(f"history {key}= requires a value")
        selectors[key] = value
    return selectors


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


def execute_and_print(runner: Runner, command: str) -> int:
    """Execute one command line for top-level `bywaf run` callers."""
    try:
        state = new_shell_state(runner)
        events = runner.execute(command)
        process_framework_requests(runner, state)
        print_events(events)
    except SystemExit as exc:
        if exc.code in (0, None):
            return 0
        print(f"error: command failed with exit code {exc.code}")
        return int(exc.code) if isinstance(exc.code, int) else 1
    except (NmapUnavailableError, NmapScanError) as exc:
        print(f"error: {exc}")
        return 1
    except (KeyError, ValueError) as exc:
        print(f"error: {friendly_error(exc)}")
        return 1
    return 0


def command_from_remainder(tokens: list[str]) -> str:
    """Build a command string from argparse REMAINDER tokens.

    A single token is already a shell-preserved command string, which matters
    for quoted pipelines such as `bywaf run 'a | b'`.
    """
    if not tokens:
        raise ValueError("run requires a command")
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(shlex.quote(token) for token in tokens)


def run_remainder(runner: Runner, tokens: list[str]) -> int:
    """Validate and run the token remainder from `bywaf run ...`."""
    try:
        command = command_from_remainder(tokens)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    status = 0
    for one_command in split_command_sequence(command) or [command]:
        status = execute_and_print(runner, one_command)
        if status != 0:
            return status
    return status


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


def print_vars(runner: Runner, state: ShellState) -> None:
    """Print session variables in stable key order."""
    del state
    for key, value in runner.registry.varstore.items():
        print(f"{key}={display_var_value(runner, value)}")


def print_var(runner: Runner, state: ShellState, name: str) -> None:
    """Print one session variable after applying active-context scoping."""
    key = resolve_var_key(state, name.strip())
    value = runner.registry.varstore.get(key)
    if value is None:
        print(f"error: variable not set: {key}")
        return
    print(f"{key}={display_var_value(runner, value)}")


def set_var(runner: Runner, state: ShellState, assignment: str) -> None:
    """Set a REPL variable, keeping secret-looking values out of varstore."""
    key, value = assignment.split("=", 1)
    resolved_key = resolve_var_key(state, key.strip())
    cleaned_value = value.strip()
    if is_secret_name(resolved_key.rsplit(".", 1)[-1]):
        secret_ref = runner.registry.secrets.put(
            resolved_key,
            cleaned_value,
            key=load_or_create_fingerprint_key(),
            source="vars",
        )
        runner.registry.varstore.set(resolved_key, secret_ref.ref)
        runner.db.store_secret(secret_ref, cleaned_value)
        if not runner.db.encrypted:
            print(f"warning: storing secret variable {resolved_key} in plaintext database {runner.db.path}")
        print(f"{resolved_key}={REDACTED_VALUE} fingerprint={secret_ref.fingerprint.format()}")
        return
    runner.registry.varstore.set(resolved_key, cleaned_value)


def display_var_value(runner: Runner, value: str) -> str:
    """Return a variable value with in-memory secret references redacted."""
    secret_ref = runner.registry.secrets.metadata(value)
    if secret_ref is None:
        if value.startswith(SECRET_REF_PREFIX):
            return f"{REDACTED_VALUE} fingerprint=unavailable"
        return value
    return f"{REDACTED_VALUE} fingerprint={secret_ref.fingerprint.format()}"


def set_active_context(runner: Runner, state: ShellState, target: str) -> None:
    """Set the active commandlet context for short variable assignments."""
    if target == "global":
        state.active_context = None
        if state.completer is not None:
            state.completer.active_context = None
        print("using global")
        return
    commandlet = target.split(".", 1)[-1]
    if commandlet not in runner.registry.plugins:
        raise ValueError(f"unknown commandlet context: {target}")
    state.active_context = commandlet
    if state.completer is not None:
        state.completer.active_context = commandlet
    print(f"using {commandlet}")


def resolve_var_key(state: ShellState, key: str) -> str:
    """Resolve unqualified variable keys through the active `use` context."""
    if "." in key or key.startswith("global."):
        return key
    if state.active_context:
        return f"{state.active_context}.{key}"
    return key


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


def split_command_sequence(line: str) -> list[str]:
    """Split semicolon-separated commands while preserving quoted semicolons."""
    commands: list[str] = []
    quote: str | None = None
    escaped = False
    current: list[str] = []
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            continue
        if char == ";":
            command = "".join(current).strip()
            if command:
                commands.append(command)
            current = []
            continue
        current.append(char)
    command = "".join(current).strip()
    if command:
        commands.append(command)
    return commands


def line_has_continuation(line: str) -> bool:
    """Return whether a physical line ends with an unescaped continuation slash."""
    stripped = line.rstrip()
    backslashes = len(stripped) - len(stripped.rstrip("\\"))
    return backslashes % 2 == 1


def remove_line_continuation(line: str) -> str:
    """Remove one trailing continuation slash from a physical line."""
    stripped = line.rstrip()
    return stripped[:-1]


def record_command_history(
    command: str,
    path: Path = DEFAULT_HISTORY,
    session_history: list[str] | None = None,
    timestamp_format: str = DEFAULT_HISTORY_TIMESTAMP_FORMAT,
    stored_command: str | None = None,
) -> str | None:
    """Append a command to persistent history and the in-memory session list."""
    if not command.strip():
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime(timestamp_format).strip()
    entry = f"{stored_command or command}  # {timestamp}"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{entry}\n")
    if session_history is not None:
        session_history.append(entry)
    return entry


def redact_history_command(command: str) -> str:
    """Return a history-safe command with obvious secret assignments removed."""
    if "=" not in command:
        return command
    result = redact_command_text(command, key=load_or_create_fingerprint_key())
    return result.command


def render_prompt(pattern: str) -> str:
    """Render prompt placeholders using local process and host metadata."""
    user = os.getenv("USER", "")
    host_full = socket.gethostname()
    replacements = {
        "%u": user,
        "%h": host_full.split(".", 1)[0],
        "%H": host_full,
        "%m": platform.machine(),
        "%T": datetime.now().strftime("%H:%M:%S"),
    }
    prompt = pattern
    for key, value in replacements.items():
        prompt = prompt.replace(key, value)
    return prompt
