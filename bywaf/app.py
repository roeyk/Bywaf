"""Top-level CLI and REPL."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import shlex
import socket
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import __version__
from .completion import Completer, install_readline
from .config import Settings
from .db import EventStore
from .nmap_backend import NmapScanError, NmapUnavailableError
from .plugin import CommandContext
from .registry import PluginRegistry
from .runner import Runner, add_runner_arguments

@dataclass(frozen=True, slots=True)
class HelpEntry:
    command: str
    description: str
    usage: str
    examples: tuple[str, ...] = ()


HELP_COMMANDS = (
    HelpEntry("help, ?", "show this help", "help [command]"),
    HelpEntry("plugins", "list loaded plugin providers", "plugins"),
    HelpEntry("cmds", "show commandlets grouped by plugin provider", "cmds"),
    HelpEntry("history", "show command history", "history"),
    HelpEntry("jobs", "show background jobs", "jobs"),
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
    HelpEntry("save db=<path>", "save active SQLite database", "save db=<path>"),
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
    prompt_pattern: str = "bywaf> "
    history_path: Path = field(default_factory=lambda: DEFAULT_HISTORY)
    session_history: list[str] = field(default_factory=list)

    def prompt(self) -> str:
        return render_prompt(self.prompt_pattern)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bywaf")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE), help="SQLite database path")
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
) -> Runner:
    registry = PluginRegistry.discover()
    if plugin_root and plugin_config:
        filesystem = PluginRegistry.from_config(
            Path(plugin_root),
            Path(plugin_config),
            varstore=registry.varstore,
        )
        registry.plugins.update(filesystem.plugins)
    return Runner(EventStore(Path(database)), registry)


def format_event(event) -> str:
    return f"#{event.id} {event.topic} {event.payload}"


def shutdown_runner(runner: Runner) -> None:
    runner.db.checkpoint()


def repl(runner: Runner) -> None:
    state = ShellState()
    install_readline(Completer(runner.registry, runner.db))
    try:
        while True:
            try:
                line = input(state.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            record_command_history(
                line,
                state.history_path,
                state.session_history,
                runner.registry.varstore.get(HISTORY_TIMESTAMP_FORMAT_VAR, DEFAULT_HISTORY_TIMESTAMP_FORMAT),
            )
            if dispatch_repl_line(runner, line, state) == "exit":
                return
    finally:
        shutdown_runner(runner)


def dispatch_repl_line(runner: Runner, line: str, state: ShellState | None = None) -> str | None:
    state = state or ShellState()
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
                print_jobs(runner)
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
                print_events(runner.db.events_matching(command_run_id=target.split("=", 1)[1]))
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
                state.prompt_pattern = pattern
            case ["load", spec]:
                load_repl_resource(runner, spec, state)
            case ["save"]:
                print("usage: save db=<path>, save config=<path>, or save history=<path>")
            case ["save", spec]:
                save_repl_resource(runner, spec, state)
            case ["run", command]:
                print_events(runner.execute(command))
            case [name, *_] if name in runner.registry.plugins:
                print_events(runner.execute(line))
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


def friendly_error(exc: Exception) -> str:
    if isinstance(exc, KeyError):
        return str(exc).strip("'")
    return str(exc)


def print_events(events) -> None:
    for event in events:
        print(format_event(event))


def print_history(entries: Sequence[str] = ()) -> None:
    for entry in entries:
        print(entry)


def execute_and_print(runner: Runner, command: str) -> int:
    try:
        print_events(runner.execute(command))
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
    if not tokens:
        raise ValueError("run requires a command")
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(shlex.quote(token) for token in tokens)


def run_remainder(runner: Runner, tokens: list[str]) -> int:
    try:
        command = command_from_remainder(tokens)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    return execute_and_print(runner, command)


def print_help(runner: Runner, command: str | None = None) -> None:
    if command:
        print_command_help(runner, command)
        return
    width = max(len(entry.command) for entry in HELP_COMMANDS)
    for entry in HELP_COMMANDS:
        print(f"{entry.command:<{width}}  {entry.description}")


def print_command_help(runner: Runner, command: str) -> None:
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
    for entry in HELP_COMMANDS:
        aliases = [part.strip().split()[0] for part in entry.command.split(",")]
        if command in aliases:
            return entry
    return None


def print_help_entry(entry: HelpEntry) -> None:
    print(f"Command: {entry.command}")
    print(f"Usage:   {entry.usage}")
    if entry.examples:
        print("Examples:")
        for example in entry.examples:
            print(f"  {example}")
    print()
    print(entry.description)


def print_plugin_argparse_help(runner: Runner, plugin) -> None:
    context = CommandContext(runner.db, source=plugin.spec.name, varstore=runner.registry.varstore)
    try:
        list(plugin.run(context, ["--help"], []))
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def print_jobs(runner: Runner) -> None:
    for row in runner.db.jobs():
        print(f"#{row['id']} pid={row['pid']} status={row['status']} {row['command_line']}")


def print_runs(runner: Runner) -> None:
    for row in runner.db.runs():
        print(
            f"{row['command_run_id']} pipeline={row['pipeline_id']} "
            f"source={row['source']} events={row['events']}"
        )


def print_job(runner: Runner, job_id: str) -> None:
    for row in runner.db.jobs():
        if str(row["id"]) == job_id:
            print(f"#{row['id']} pid={row['pid']} status={row['status']} {row['command_line']}")
            return
    print(f"error: unknown job: {job_id}")


def print_vars(runner: Runner) -> None:
    for key, value in runner.registry.varstore.items():
        print(f"{key}={value}")


def print_topics(runner: Runner) -> None:
    for topic in runner.db.topics():
        print(topic)


def print_commandlets(runner: Runner) -> None:
    for provider, commandlets in runner.registry.grouped_names().items():
        print(provider)
        for commandlet in commandlets:
            print(f"  {commandlet}")


def load_repl_resource(runner: Runner, spec: str, state: ShellState | None = None) -> None:
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
    state = state or ShellState()
    match spec.split("=", 1):
        case ["db", value]:
            save_database(runner, resolve_resource_path(value, Path("."), DEFAULT_DATABASE))
        case ["config", value]:
            save_config(runner, resolve_resource_path(value, Path("."), DEFAULT_CONFIG))
        case ["history", value]:
            save_history(state, resolve_resource_path(value, Path("."), DEFAULT_HISTORY))
        case _:
            print("usage: save db=<path>, save config=<path>, or save history=<path>")


def save_database(runner: Runner, path: Path) -> None:
    copy_sqlite_database(runner.db.path, path)
    print(f"saved db={path}")


def load_database(runner: Runner, path: Path) -> None:
    runner.db = EventStore(path)
    print(f"loaded db={path}")


def copy_sqlite_database(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with EventStore(source).connect() as source_conn:
        with EventStore(destination).connect() as dest_conn:
            source_conn.backup(dest_conn)


def save_config(runner: Runner, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(runner.registry.varstore.values, indent=2, sort_keys=True) + "\n")
    print(f"saved config={path}")


def load_config(runner: Runner, path: Path) -> None:
    values = json.loads(path.read_text())
    if not isinstance(values, dict):
        raise ValueError(f"{path} must contain a JSON object")
    runner.registry.varstore.values.clear()
    for key, value in values.items():
        runner.registry.varstore.set(str(key), value)
    print(f"loaded config={path}")


def save_history(state: ShellState, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(state.session_history)
    path.write_text(f"{text}\n" if text else "")
    print(f"saved history={path}")


def load_history(state: ShellState, path: Path) -> None:
    state.history_path = path
    state.session_history = path.read_text().splitlines() if path.exists() else []
    print(f"loaded history={path}")


def is_explicit_path(value: str) -> bool:
    return (
        value.startswith(("./", "../", "~/"))
        or Path(value).is_absolute()
    )


def resolve_resource_path(value: str, root: Path, default: Path | None = None) -> Path:
    if not value:
        if default is None:
            raise ValueError("resource path is required")
        return default.expanduser()
    path = Path(value).expanduser()
    if is_explicit_path(value):
        return path
    return root / path


def run_script(runner: Runner, path: Path, state: ShellState | None = None) -> None:
    state = state or ShellState()
    for line_number, command in script_commands(path):
        print(f"{path}:{line_number}: {command}")
        if dispatch_repl_line(runner, command, state) == "exit":
            return


def script_commands(path: Path) -> list[tuple[int, str]]:
    commands: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = strip_inline_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        commands.append((line_number, line))
    return commands


def strip_inline_comment(line: str) -> str:
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
                print_jobs(runner)
            case _:
                parser.error(f"unknown subcommand: {args.subcommand}")
        return 0
    finally:
        shutdown_runner(runner)
