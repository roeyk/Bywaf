"""REPL help rendering.

Provides built-in help entries and rendering helpers for shell commands that are
not backed by plugin commandlets.

Used by:
- repl.commands: implement `help` and `?`.
- tests: assert stable operator-facing help text."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from ...plugin import CommandContext
from ...runner import Runner
from ...style import ansi_color

HELP_COLOR_MODE_VAR = "display.help.color"
HELP_COMMAND_COLOR_VAR = "display.help.command-color"
DEFAULT_HELP_COLOR_MODE = "auto"
DEFAULT_HELP_COMMAND_COLOR = "green"


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
    HelpEntry("info", "show active jobs, pipelines, and steps", "info"),
    HelpEntry("run", "execute the active commandlet selected by use", "run", ("use http_headers", "run")),
    HelpEntry(
        "set [--secret] [name[=value]]",
        "list, show, or set session variables",
        "set [--secret] [name[=value]]",
        (
            "set http/http_probe.cookie-file=/tmp/cookies.txt",
            "set --secret network/ssh_probe.password=",
        ),
    ),
    HelpEntry("topics", "list event topics in the active database", "topics"),
    HelpEntry(
        "project, proj",
        "list, inspect, create, switch, archive, or export project directories",
        "project <list|info|new|use|archive|export>",
    ),
    HelpEntry("use <commandlet|global>", "set the active variable context", "use <commandlet|global>"),
    HelpEntry(
        "event",
        "show events for a topic, job, step, pipeline, serial, or event id",
        "event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...] [sort=key]",
        (
            "event 123",
            "event host.found",
            "event port.open host=192.0.2.10 sort=host",
            "event step=1",
            "event pipeline=1",
            "event serial=hostscanner-...",
        ),
        "event <selector>",
    ),
    HelpEntry(
        "events [tail|--tail] [last=N]",
        "show recent events",
        "events [tail|--tail] [last=N]",
        ("events", "events tail", "events tail last=50"),
    ),
    HelpEntry("prompt [pattern]", "show or set prompt pattern", "prompt [pattern]", ("prompt $Y$M$D $h:$m:$s $Z%F> ",)),
    HelpEntry("plugin", "load filesystem plugins", "plugin load=<path> [--force]"),
    HelpEntry("pload", "short alias for plugin load", "pload <path> [--force]"),
    HelpEntry("config", "load or save session configuration", "config <load|save> file=<path> [--encrypt]"),
    HelpEntry("history", "show, load, or save command history", "history [since=... until=...] | history <load|save> file=<path> [--encrypt]"),
    HelpEntry("script", "load/run or save REPL scripts", "script <load|save> file=<path> [--encrypt]"),
    HelpEntry("exec <argv...>", "execute an OS command", "exec <argv...>", ("exec ls -la",)),
    HelpEntry("<plugin pipeline>", "run commandlets directly", "<plugin pipeline>", ("hostscanner 127.0.0.1 | portscanner",)),
    HelpEntry("exit, quit, q", "exit the shell", "exit"),
)


def print_help(runner: Runner, command: str | None = None) -> None:
    """Print built-in help or delegate commandlet help."""
    if command:
        print_command_help(runner, command)
        return
    width = max(len(entry.summary or entry.command) for entry in HELP_COMMANDS)
    for entry in HELP_COMMANDS:
        name = entry.summary or entry.command
        command_text = f"{name:<{width}}"
        print(f"{format_help_command(runner, command_text)}  {entry.description}")


def print_command_help(runner: Runner, command: str) -> None:
    """Show help for either a plugin commandlet or shell built-in."""
    if runner.registry.has_commandlet(command):
        plugin = runner.registry.get(command)
        print_plugin_argparse_help(runner, plugin)
        return
    entry = find_help_entry(command)
    if entry:
        print_help_entry(runner, entry)
        return
    print(f"error: unknown command: {command}")


def find_help_entry(command: str) -> HelpEntry | None:
    """Find built-in help by command name or alias."""
    for entry in HELP_COMMANDS:
        aliases = [part.strip().split()[0] for part in entry.command.split(",")]
        if command in aliases:
            return entry
    return None


def print_help_entry(runner: Runner, entry: HelpEntry) -> None:
    """Render one built-in help entry."""
    print(f"Command: {format_help_command(runner, entry.command)}")
    print(f"Usage:   {entry.usage}")
    if entry.examples:
        print("Examples:")
        for example in entry.examples:
            print(f"  {example}")
    print()
    print(entry.description)


def format_help_command(runner: Runner | None, command: str) -> str:
    """Return a built-in help command name with optional ANSI color."""
    if runner is None or not help_color_enabled(runner):
        return command
    color = runner.registry.varstore.get(HELP_COMMAND_COLOR_VAR, DEFAULT_HELP_COMMAND_COLOR) or DEFAULT_HELP_COMMAND_COLOR
    return ansi_color(command, color)


def help_color_enabled(runner: Runner) -> bool:
    """Return whether help listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(HELP_COLOR_MODE_VAR, DEFAULT_HELP_COLOR_MODE) or DEFAULT_HELP_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


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
