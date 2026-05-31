"""Built-in REPL command dispatch table.

Provides the small command-name-to-handler map used by the interactive shell.
The larger command families live in focused sibling modules so parser,
resource, plugin, event, and variable behavior can evolve independently.

Used by:
- bywaf.repl.shell: dispatches parsed REPL lines to these handlers.
- tests: import execution helpers through this stable facade.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..command.names import PROJECT_ALIAS_COMMAND, SET_COMMAND, SETG_COMMAND
from ..runner import Runner
from .command.events import handle_event_command, handle_events_command
from .command.exec import (
    execute_repl_commandlet as execute_repl_commandlet,
    execute_shell_command as execute_shell_command,
    handle_exec_command,
    handle_run_command,
    visible_commandlet_events as visible_commandlet_events,
)
from .command.plugins import handle_pload_command, handle_plugin_command
from .command.resources import handle_config_command, handle_history_command, handle_pref_command, handle_project_command, handle_script_command
from .command.vars import handle_setg_command, handle_use_command, handle_vars_command
from .display import print_commandlets, print_help, print_info, print_plugins, print_topics, print_triggers

if TYPE_CHECKING:
    from .state import ShellState


ReplCommandHandler = Callable[[Runner, Any, str | None, str], str | None]


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
    print_plugins(runner)
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


def handle_info_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print runtime overview."""
    del state, rest, line
    print_info(runner)
    return None


def handle_topics_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print event topics."""
    del state, line
    print_topics(runner, rest or "")
    return None


def handle_prompt_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or set the prompt pattern."""
    del line
    if rest is None:
        print(state.prompt_pattern)
    else:
        set_prompt_pattern(runner, state, rest, source="user")
    return None


def set_prompt_pattern(runner: Runner, state: ShellState, pattern: str, *, source: str) -> None:
    """Set the REPL prompt and record the change as an auditable event."""
    old_prompt = state.prompt_pattern
    state.prompt_pattern = pattern
    runner.events.publish(
        "shell.prompt.updated",
        {"old_prompt": old_prompt, "new_prompt": pattern, "source": source},
        "framework",
    )


REPL_COMMAND_HANDLERS: dict[str, ReplCommandHandler] = {
    "?": handle_help_command,
    "cmds": handle_cmds_command,
    "config": handle_config_command,
    "event": handle_event_command,
    "events": handle_events_command,
    "exec": handle_exec_command,
    "exit": handle_exit_command,
    "help": handle_help_command,
    "history": handle_history_command,
    "info": handle_info_command,
    "plugin": handle_plugin_command,
    "plugins": handle_plugins_command,
    "pload": handle_pload_command,
    "pref": handle_pref_command,
    "project": handle_project_command,
    PROJECT_ALIAS_COMMAND: handle_project_command,
    "prompt": handle_prompt_command,
    "q": handle_exit_command,
    "quit": handle_exit_command,
    "run": handle_run_command,
    "script": handle_script_command,
    "topics": handle_topics_command,
    "triggers": handle_triggers_command,
    "use": handle_use_command,
    SET_COMMAND: handle_vars_command,
    SETG_COMMAND: handle_setg_command,
}
