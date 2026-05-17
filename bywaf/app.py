"""Top-level CLI and REPL."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import shlex
import socket
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import __version__
from .completion import Completer, install_readline
from .config import Settings
from .db import EventStore, Subscription, database_appears_encrypted, export_encrypted_database, export_plaintext_database
from .nmap_backend import NmapScanError, NmapUnavailableError
from .plugin import CommandContext, normalize_argv, run_process_argv
from .registry import PluginRegistry
from .runner import Runner, add_runner_arguments

@dataclass(frozen=True, slots=True)
class HelpEntry:
    """Help text for REPL built-ins that are not backed by commandlets."""

    command: str
    description: str
    usage: str
    examples: tuple[str, ...] = ()


HELP_COMMANDS = (
    HelpEntry("help, ?", "show this help", "help [command]"),
    HelpEntry("plugins", "list loaded plugin providers", "plugins"),
    HelpEntry("cmds", "show commandlets grouped by plugin provider", "cmds"),
    HelpEntry("history", "show command history", "history"),
    HelpEntry("jobs", "alias for job list", "jobs"),
    HelpEntry("runs", "show commandlet run IDs", "runs"),
    HelpEntry("vars [name=value]", "list or set session variables", "vars [name=value]", ("vars http_probe.cookie-file=/tmp/cookies.txt",)),
    HelpEntry("topics", "list event topics in the active database", "topics"),
    HelpEntry("show <topic|job=id|run=id|pipeline=id>", "show events for a topic, job, run, or pipeline", "show <topic|job=id|run=id|pipeline=id>", ("show host.found", "show run=hostscanner-...", "show pipeline=pipeline-...")),
    HelpEntry("prompt [pattern]", "show or set prompt pattern", "prompt [pattern]", ("prompt %u@%h %T > ",)),
    HelpEntry("load plugin=<path>", "load a filesystem plugin", "load plugin=<path>"),
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

DEFAULT_SETTINGS = Settings()
DEFAULT_DATABASE = DEFAULT_SETTINGS.database
DEFAULT_CONFIG = DEFAULT_SETTINGS.config
DEFAULT_HISTORY = DEFAULT_SETTINGS.history
DEFAULT_PLUGIN_DIR = DEFAULT_SETTINGS.plugin_dir
DEFAULT_SCRIPT_DIR = DEFAULT_SETTINGS.script_dir
DEFAULT_DATABASE_DIR = DEFAULT_SETTINGS.database_dir
DEFAULT_CONFIG_DIR = DEFAULT_SETTINGS.config_dir
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

    def prompt(self) -> str:
        return render_prompt(self.prompt_pattern)


def build_parser() -> argparse.ArgumentParser:
    """Build the non-interactive command-line interface."""

    parser = argparse.ArgumentParser(prog="bywaf")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE), help="SQLite database path")
    parser.add_argument("--encrypted", action="store_true", help="open or create the database with SQLCipher encryption")
    parser.add_argument("--plugin-root", help="directory containing filesystem plugins")
    parser.add_argument("--plugin-config", help="JSON or simple YAML plugin config")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    subparsers = parser.add_subparsers(dest="subcommand")
    add_runner_arguments(subparsers.add_parser("run", help="run a commandlet pipeline"))
    subparsers.add_parser("plugins", help="list loaded plugin providers")
    subparsers.add_parser("cmds", help="show commandlets grouped by plugin provider")
    subparsers.add_parser("history", help="show command history")
    subparsers.add_parser("jobs", help="show background jobs")
    subparsers.add_parser("repl", help="start interactive shell")
    return parser


def make_runner(
    database: str | Path,
    *,
    plugin_root: str | Path | None = None,
    plugin_config: str | Path | None = None,
    encrypted: bool = False,
    passphrase: str | None = None,
) -> Runner:
    """Create a runner with stock plugins plus optional filesystem plugins."""

    database_path = Path(database)
    db_passphrase = passphrase
    if db_passphrase is None and (encrypted or database_appears_encrypted(database_path)):
        db_passphrase = prompt_database_passphrase(database_path, creating=encrypted)
    registry = PluginRegistry.discover()
    if plugin_root and plugin_config:
        filesystem = PluginRegistry.from_config(
            Path(plugin_root),
            Path(plugin_config),
            varstore=registry.varstore,
        )
        registry.plugins.update(filesystem.plugins)
    return Runner(EventStore(database_path, passphrase=db_passphrase), registry)


def format_event(event) -> str:
    """Render one event row for human-readable console output."""

    return f"#{event.id} {event.topic} {event.payload}"


def shutdown_runner(runner: Runner) -> None:
    """Flush SQLite WAL state before the process exits."""

    runner.db.checkpoint()


def repl(runner: Runner) -> None:
    """Run the interactive shell until EOF, interrupt, or an exit command."""

    state = ShellState()
    install_readline(Completer(runner.registry, runner.db))
    try:
        while True:
            process_framework_requests(runner, state)
            try:
                line = read_logical_input(state).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            record_command_history(
                line,
                state.history_path,
                state.session_history,
                runner.registry.varstore.get(
                    HISTORY_TIMESTAMP_FORMAT_VAR,
                    DEFAULT_HISTORY_TIMESTAMP_FORMAT,
                ) or DEFAULT_HISTORY_TIMESTAMP_FORMAT,
            )
            if dispatch_repl_line(runner, line, state) == "exit":
                return
            process_framework_requests(runner, state)
    finally:
        shutdown_runner(runner)


def read_logical_input(state: ShellState) -> str:
    """Read one logical REPL command, joining backslash continuations."""
    lines: list[str] = []
    prompt = state.prompt()
    while True:
        line = input(prompt)
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
    state = state or ShellState(framework_request_after_id=runner.db.latest_event_id())
    commands = split_command_sequence(line)
    if len(commands) > 1:
        for command in commands:
            if dispatch_repl_line(runner, command, state) == "exit":
                return "exit"
        return None
    try:
        match line.split(maxsplit=1):
            case []:
                return None
            case ["exit"] | ["quit"] | ["q"]:
                return "exit"
            case ["help"] | ["?"]:
                print_help(runner)
            case ["help", command] | ["?", command]:
                print_help(runner, command)
            case ["plugins"]:
                print("\n".join(runner.registry.provider_names()))
            case ["cmds"]:
                print_commandlets(runner)
            case ["history"]:
                print_history(state.session_history)
            case ["jobs"]:
                events = runner.execute("job list")
                process_framework_requests(runner, state)
                print_events(events)
            case ["runs"]:
                print_runs(runner)
            case ["vars"]:
                print_vars(runner)
            case ["vars", assignment] if "=" in assignment:
                key, value = assignment.split("=", 1)
                runner.registry.varstore.set(key.strip(), value.strip())
            case ["vars", _]:
                print("usage: vars [name=value]")
            case ["topics"]:
                print_topics(runner)
            case ["show", target] if target.startswith("job="):
                print_job(runner, target.split("=", 1)[1])
            case ["show", target] if target.startswith("run="):
                run_id = target.split("=", 1)[1]
                print_run_variables(runner, run_id)
                print_events(runner.db.events_matching(command_run_id=run_id))
            case ["show", target] if target.startswith("pipeline="):
                print_events(runner.db.events_matching(pipeline_id=target.split("=", 1)[1]))
            case ["show", target] if target.startswith("topic="):
                print_events(runner.db.events_matching(topic=target.split("=", 1)[1]))
            case ["show", topic]:
                print_events(runner.db.events_for_topic(topic))
            case ["show"]:
                print("usage: show <topic>")
            case ["prompt"]:
                print(state.prompt_pattern)
            case ["prompt", pattern]:
                set_prompt_pattern(runner, state, pattern, source="user")
            case ["load", spec]:
                load_repl_resource(runner, spec, state)
            case ["save"]:
                print("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
            case ["save", spec]:
                save_repl_resource(runner, spec, state)
            case ["run", command]:
                events = runner.execute(command)
                process_framework_requests(runner, state)
                print_events(events)
            case [name, *_] if name in runner.registry.plugins:
                events = runner.execute(line)
                process_framework_requests(runner, state)
                print_events(events)
            case [name, *_]:
                print(f"error: unknown command or commandlet: {name}")
    except SystemExit as exc:
        if exc.code not in (0, None):
            print(f"error: command failed with exit code {exc.code}")
    except (NmapUnavailableError, NmapScanError) as exc:
        print(f"error: {exc}")
    except (KeyError, ValueError) as exc:
        print(f"error: {friendly_error(exc)}")
    except Exception as exc:
        print(f"error: {exc}")
    return None


def process_framework_requests(runner: Runner, state: ShellState) -> None:
    """Apply interpreter-owned requests that plugins wrote to the event bus."""
    for event in runner.db.fetch(
        Subscription(
            topics=(
                "shell.prompt.requested",
                "framework.console.alert.requested",
                "framework.console.output.requested",
                "framework.file.page.requested",
                "framework.process.run.requested",
                "framework.process.stream.requested",
            ),
            after_id=state.framework_request_after_id,
            limit=1000,
        )
    ):
        if event.id is not None:
            state.framework_request_after_id = max(state.framework_request_after_id, event.id)
        if event.id is None or event.id in state.handled_request_ids:
            continue
        state.handled_request_ids.add(event.id)
        handle_framework_request(runner, state, event)


def handle_framework_request(runner: Runner, state: ShellState, event) -> None:
    """Validate and apply one framework request event."""
    handler = FRAMEWORK_REQUEST_HANDLERS.get(event.topic)
    if handler is None:
        deny_framework_request(runner, event, f"unsupported request topic: {event.topic}")
        return
    handler(runner, state, event)


def handle_prompt_request(runner: Runner, state: ShellState, event) -> None:
    """Validate and apply a prompt-change request."""
    requested_prompt = event.payload.get("prompt")
    if isinstance(requested_prompt, str) and requested_prompt:
        old_prompt = state.prompt_pattern
        state.prompt_pattern = requested_prompt
        runner.db.publish(
            "shell.prompt.updated",
            {
                "old_prompt": old_prompt,
                "new_prompt": requested_prompt,
                "request_event_id": event.id,
            },
            "framework",
        )
        return
    deny_framework_request(runner, event, "prompt must be a non-empty string")


def emit_console_alert(runner: Runner, event) -> None:
    """Validate, audit, and display a plugin-requested console alert."""
    message = event.payload.get("message")
    if not isinstance(message, str) or not message:
        deny_framework_request(runner, event, "alert message must be a non-empty string")
        return
    level = event.payload.get("level", "alert")
    if not isinstance(level, str) or not level:
        deny_framework_request(runner, event, "alert level must be a non-empty string")
        return
    source = event.payload.get("source")
    if not isinstance(source, str) or not source:
        source = event.source
    command_id = event.command_run_id or event.payload.get("command_run_id") or "interactive"
    payload = {
        "message": message,
        "level": level,
        "source": source,
        "job_id": event.payload.get("job_id"),
        "request_event_id": event.id,
    }
    runner.db.publish(
        "console.alert",
        payload,
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    if not bool(event.payload.get("silent")):
        print(f"{source} <{command_id}>: {message}", flush=True)


def handle_console_alert_request(runner: Runner, state: ShellState, event) -> None:
    """Handle a console-alert framework request."""
    del state
    emit_console_alert(runner, event)


def emit_console_output(runner: Runner, event) -> None:
    """Validate, audit, and display plugin-requested command output."""
    text = event.payload.get("text", "")
    end = event.payload.get("end", "\n")
    if not isinstance(text, str):
        deny_framework_request(runner, event, "console output text must be a string")
        return
    if not isinstance(end, str):
        deny_framework_request(runner, event, "console output end must be a string")
        return
    runner.db.publish(
        "console.output",
        {
            "text": text,
            "end": end,
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    print(text, end=end, flush=True)


def handle_console_output_request(runner: Runner, state: ShellState, event) -> None:
    """Handle a console-output framework request."""
    del state
    emit_console_output(runner, event)


def handle_file_page_request(runner: Runner, state: ShellState, event) -> None:
    """Validate, audit, and display a plugin-requested local file page."""
    del state
    raw_path = event.payload.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        deny_framework_request(runner, event, "page path must be a non-empty string")
        return
    path = Path(raw_path).expanduser()
    if not path.exists():
        deny_framework_request(runner, event, f"{path} does not exist")
        return
    if path.is_dir():
        deny_framework_request(runner, event, f"{path} is a directory")
        return
    if bool(event.payload.get("background")):
        deny_framework_request(runner, event, "file paging requires a foreground commandlet")
        return
    runner.db.publish(
        "console.page",
        {
            "path": str(path),
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )
    pager = shutil.which("less")
    if pager and sys.stdin.isatty() and sys.stdout.isatty():
        subprocess.run([pager, str(path)], check=False)
        return
    print(path.read_text(errors="replace"), end="", flush=True)


def handle_process_run_request(runner: Runner, state: ShellState, event) -> None:
    """Validate, execute, and audit a framework-mediated process request."""
    del state
    if bool(event.payload.get("handled")):
        return
    raw_argv = event.payload.get("argv")
    if not isinstance(raw_argv, list) or not all(isinstance(part, str) for part in raw_argv):
        deny_framework_request(runner, event, "process argv must be a list of strings")
        return
    try:
        argv = normalize_argv(raw_argv)
    except (TypeError, ValueError) as exc:
        deny_framework_request(runner, event, str(exc))
        return
    raw_cwd = event.payload.get("cwd")
    if raw_cwd is not None and not isinstance(raw_cwd, str):
        deny_framework_request(runner, event, "process cwd must be a string")
        return
    raw_timeout = event.payload.get("timeout")
    if raw_timeout is not None and not isinstance(raw_timeout, int | float):
        deny_framework_request(runner, event, "process timeout must be numeric")
        return
    try:
        completed = run_process_argv(argv, cwd=raw_cwd, timeout=raw_timeout)
    except Exception as exc:
        deny_framework_request(runner, event, str(exc))
        return
    runner.db.publish(
        "process.run",
        {
            "argv": list(argv),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "ok": completed.returncode == 0,
            "source": event.payload.get("source", event.source),
            "job_id": event.payload.get("job_id"),
            "request_event_id": event.id,
        },
        "framework",
        pipeline_id=event.pipeline_id,
        command_run_id=event.command_run_id,
        parent_command_run_id=event.parent_command_run_id,
    )


def handle_process_stream_request(runner: Runner, state: ShellState, event) -> None:
    """Handle or deny externally inserted process-stream requests."""
    del state
    if bool(event.payload.get("handled")):
        return
    deny_framework_request(
        runner,
        event,
        "process streaming requests must be handled by context.process.stream",
    )


FRAMEWORK_REQUEST_HANDLERS = {
    "shell.prompt.requested": handle_prompt_request,
    "framework.console.alert.requested": handle_console_alert_request,
    "framework.console.output.requested": handle_console_output_request,
    "framework.file.page.requested": handle_file_page_request,
    "framework.process.run.requested": handle_process_run_request,
    "framework.process.stream.requested": handle_process_stream_request,
}


def deny_framework_request(runner: Runner, event, reason: str) -> None:
    """Record a denied framework request for auditability."""
    runner.db.publish(
        "framework.request.denied",
        {
            "request_event_id": event.id,
            "request_topic": event.topic,
            "reason": reason,
        },
        "framework",
    )


def set_prompt_pattern(runner: Runner, state: ShellState, pattern: str, *, source: str) -> None:
    """Set the REPL prompt and record the change as an auditable event."""
    old_prompt = state.prompt_pattern
    state.prompt_pattern = pattern
    runner.db.publish(
        "shell.prompt.updated",
        {"old_prompt": old_prompt, "new_prompt": pattern, "source": source},
        "framework",
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


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a command run."""
    rows = runner.db.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(f"  {row['name']}={row['value']}")


def print_history(entries: Sequence[str] = ()) -> None:
    """Print the current session history, not the full persistent history file."""
    for entry in entries:
        print(entry)


def execute_and_print(runner: Runner, command: str) -> int:
    """Execute one command line for top-level `bywaf run` callers."""
    try:
        events = runner.execute(command)
        process_framework_requests(runner, ShellState())
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
    width = max(len(entry.command) for entry in HELP_COMMANDS)
    for entry in HELP_COMMANDS:
        print(f"{entry.command:<{width}}  {entry.description}")


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
    context = CommandContext(runner.db, source=plugin.spec.name, _varstore=runner.registry.varstore)
    try:
        list(plugin.run(context, ["--help"], []))
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def print_jobs(runner: Runner) -> None:
    """Print known background jobs."""
    for row in runner.db.jobs():
        print(f"#{row['id']} pid={row['pid']} status={row['status']} {row['command_line']}")


def print_runs(runner: Runner) -> None:
    """Print command run summaries."""
    for row in runner.db.runs():
        print(
            f"{row['command_run_id']} pipeline={row['pipeline_id']} "
            f"source={row['source']} events={row['events']}"
        )


def print_job(runner: Runner, job_id: str) -> None:
    """Print one job row by ID."""
    for row in runner.db.jobs():
        if str(row["id"]) == job_id:
            print(f"#{row['id']} pid={row['pid']} status={row['status']} {row['command_line']}")
            return
    print(f"error: unknown job: {job_id}")


def print_vars(runner: Runner) -> None:
    """Print session variables in stable key order."""
    for key, value in runner.registry.varstore.items():
        print(f"{key}={value}")


def print_topics(runner: Runner) -> None:
    """Print event topics known to the active database."""
    for topic in runner.db.topics():
        print(topic)


def print_commandlets(runner: Runner) -> None:
    """Print commandlets grouped under their plugin providers."""
    for provider, commandlets in runner.registry.grouped_names().items():
        print(provider)
        for commandlet in commandlets:
            print(f"  {commandlet}")


def load_repl_resource(runner: Runner, spec: str, state: ShellState | None = None) -> None:
    """Handle `load key=value` resources from the REPL."""
    state = state or ShellState()
    match spec.split("=", 1):
        case ["db", value]:
            load_database(runner, resolve_resource_path(value, Path("."), DEFAULT_DATABASE))
        case ["config", value]:
            load_config(runner, resolve_resource_path(value, Path("."), DEFAULT_CONFIG))
        case ["history", value]:
            load_history(state, resolve_resource_path(value, Path("."), DEFAULT_HISTORY))
        case ["plugin", value] if value:
            plugin_path = resolve_resource_path(value, DEFAULT_PLUGIN_DIR)
            plugin = runner.registry.load_filesystem_entry(plugin_path.parent, plugin_path.name)
            print(f"loaded {plugin.spec.name}")
        case ["script", value] if value:
            run_script(runner, resolve_resource_path(value, Path(".")))
        case _:
            print("usage: load plugin=<path>, load script=<path>, load db=<path>, load config=<path>, or load history=<path>")


def save_repl_resource(runner: Runner, spec: str, state: ShellState | None = None) -> None:
    """Handle `save key=value` resources from the REPL."""
    state = state or ShellState()
    encrypt, resource = parse_save_spec(spec)
    match resource.split("=", 1):
        case ["db", value]:
            save_database(runner, resolve_resource_path(value, Path("."), DEFAULT_DATABASE), encrypt=encrypt)
        case ["config", value]:
            save_config(runner, resolve_resource_path(value, Path("."), DEFAULT_CONFIG))
        case ["history", value]:
            save_history(state, resolve_resource_path(value, Path("."), DEFAULT_HISTORY))
        case _:
            print("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")


def parse_save_spec(spec: str) -> tuple[bool, str]:
    """Parse built-in save options while keeping the resource syntax simple."""
    tokens = shlex.split(spec)
    encrypt = False
    resource_tokens: list[str] = []
    for token in tokens:
        match token:
            case "--encrypt":
                encrypt = True
            case _:
                resource_tokens.append(token)
    if len(resource_tokens) != 1:
        raise ValueError("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
    return encrypt, resource_tokens[0]


def save_database(runner: Runner, path: Path, *, encrypt: bool = False) -> None:
    """Copy the active SQLite database to a snapshot file."""
    if encrypt:
        passphrase = prompt_database_passphrase(path, creating=True)
        export_encrypted_database(
            runner.db.path,
            path,
            passphrase,
            source_passphrase=runner.db.passphrase,
        )
    elif runner.db.encrypted:
        if runner.db.passphrase is None:
            raise RuntimeError("encrypted database is missing its in-memory passphrase")
        export_plaintext_database(runner.db.path, path, source_passphrase=runner.db.passphrase)
    else:
        copy_sqlite_database(runner.db.path, path)
    print(f"saved db={path}")


def load_database(runner: Runner, path: Path) -> None:
    """Switch the runner to a different SQLite database file."""
    passphrase = None
    if database_appears_encrypted(path):
        passphrase = prompt_database_passphrase(path, creating=False)
    runner.db = EventStore(path, passphrase=passphrase)
    print(f"loaded db={path}")


def copy_sqlite_database(source: Path, destination: Path) -> None:
    """Use SQLite backup API instead of copying files around WAL state."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with EventStore(source).connect() as source_conn:
        with EventStore(destination).connect() as dest_conn:
            source_conn.backup(dest_conn)


def prompt_database_passphrase(path: Path, *, creating: bool) -> str:
    """Prompt for a database passphrase without ever storing it on disk."""
    action = "Create passphrase for encrypted database" if creating else "Passphrase for encrypted database"
    return getpass.getpass(f"{action} {path}: ")


def save_config(runner: Runner, path: Path) -> None:
    """Persist session variables as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(runner.registry.varstore.values, indent=2, sort_keys=True) + "\n")
    print(f"saved config={path}")


def load_config(runner: Runner, path: Path) -> None:
    """Replace session variables from a JSON object."""
    values = json.loads(path.read_text())
    if not isinstance(values, dict):
        raise ValueError(f"{path} must contain a JSON object")
    runner.registry.varstore.values.clear()
    for key, value in values.items():
        runner.registry.varstore.set(str(key), value)
    print(f"loaded config={path}")


def save_history(state: ShellState, path: Path) -> None:
    """Save current-session history lines to a script-friendly file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(state.session_history)
    path.write_text(f"{text}\n" if text else "")
    print(f"saved history={path}")


def load_history(state: ShellState, path: Path) -> None:
    """Load a history file as the current session history and append target."""
    state.history_path = path
    state.session_history = path.read_text().splitlines() if path.exists() else []
    print(f"loaded history={path}")


def is_explicit_path(value: str) -> bool:
    """Return True when resource resolution should not prepend a root."""
    return (
        value.startswith(("./", "../", "~/"))
        or Path(value).is_absolute()
    )


def resolve_resource_path(value: str, root: Path, default: Path | None = None) -> Path:
    """Resolve load/save resource names consistently.

    Plain plugin names use the plugin root; most other resource roots are `.`.
    Explicit paths such as `./x`, `../x`, `~/x`, and `/x` are used directly.
    """
    if not value:
        if default is None:
            raise ValueError("resource path is required")
        return default.expanduser()
    path = Path(value).expanduser()
    if is_explicit_path(value):
        return path
    return root / path


def run_script(runner: Runner, path: Path, state: ShellState | None = None) -> None:
    """Run one command expression per non-comment script line."""
    state = state or ShellState()
    for line_number, command in script_commands(path):
        print(f"{path}:{line_number}: {command}")
        if dispatch_repl_line(runner, command, state) == "exit":
            return


def script_commands(path: Path) -> list[tuple[int, str]]:
    """Parse a Bywaf script file into `(line_number, command)` tuples."""
    commands: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = strip_inline_comment(raw_line).rstrip()
        if not buffer and not line.strip():
            continue
        if not buffer:
            start_line = line_number
        if line_has_continuation(line):
            buffer.append(remove_line_continuation(line))
            continue
        buffer.append(line)
        logical_line = "\n".join(buffer).strip()
        for command in split_command_sequence(logical_line):
            commands.append((start_line, command))
        buffer = []
    if buffer:
        logical_line = "\n".join(buffer).strip()
        for command in split_command_sequence(logical_line):
            commands.append((start_line, command))
    return commands


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


def strip_inline_comment(line: str) -> str:
    """Remove shell-style `#` comments while preserving quoted hashes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in ("'", '"'):
            quote = None if quote == char else char if quote is None else quote
            continue
        if char == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def record_command_history(
    command: str,
    path: Path = DEFAULT_HISTORY,
    session_history: list[str] | None = None,
    timestamp_format: str = DEFAULT_HISTORY_TIMESTAMP_FORMAT,
) -> str | None:
    """Append a command to persistent history and the in-memory session list."""
    if not command.strip():
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime(timestamp_format).strip()
    entry = f"{command}  # {timestamp}"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{entry}\n")
    if session_history is not None:
        session_history.append(entry)
    return entry


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


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by `python -m bywaf` and the console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(__version__)
        return 0
    settings = Settings(database=Path(args.database))
    runner = make_runner(
        settings.database,
        plugin_root=args.plugin_root,
        plugin_config=args.plugin_config,
        encrypted=args.encrypted,
    )
    if args.subcommand in ("repl", None):
        repl(runner)
        return 0
    try:
        match args.subcommand:
            case "run":
                return run_remainder(runner, args.command)
            case "plugins":
                print("\n".join(runner.registry.provider_names()))
            case "cmds":
                print_commandlets(runner)
            case "history":
                print_history()
            case "jobs":
                print_events(runner.execute("job list"))
            case _:
                parser.error(f"unknown subcommand: {args.subcommand}")
        return 0
    finally:
        shutdown_runner(runner)
