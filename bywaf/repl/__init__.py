"""REPL package public exports.

Provides the stable `bywaf.repl` import surface while implementation lives in
cohesive sibling modules such as shell, commands, display, and resources.

Used by:
- interactive REPL commands, app-dispatch helpers, and display tests.
- operators who inspect runtime state through built-in commands.
"""


from .display import display_var_value
from .display import format_event
from .display import format_history_entry
from .display import friendly_error
from .display import print_commandlets
from .display import print_events
from .display import print_history
from .display import print_plugin_graph
from .display import print_triggers
from .dispatch import dispatch_repl_line
from .parsing import command_from_remainder
from .parsing import line_has_continuation
from .parsing import remove_line_continuation
from .parsing import split_command_sequence
from .state import DEFAULT_HISTORY_TS_FORMAT
from .state import HISTORY_TIMESTAMP_FORMAT_VAR
from .state import ShellState
from .state import new_shell_state
from .state import render_prompt
from .shell import build_input_reader
from .shell import confirm_repl_exit
from .shell import execute_and_print
from .shell import process_framework_requests
from .shell import read_logical_input
from .shell import record_command_history
from .shell import redact_history_command
from .shell import repl
from .shell import run_commandlet_remainder
from .shell import run_remainder
from .shell import shutdown_runner
from .commands import set_prompt_pattern

# Public REPL facade.  The shell, display, and command helpers are split into
# separate modules, but `bywaf.app` and older tests import them from
# `bywaf.repl` as the stable package boundary.
__all__ = [
    "DEFAULT_HISTORY_TS_FORMAT",
    "HISTORY_TIMESTAMP_FORMAT_VAR",
    "ShellState",
    "build_input_reader",
    "command_from_remainder",
    "confirm_repl_exit",
    "dispatch_repl_line",
    "display_var_value",
    "execute_and_print",
    "format_event",
    "format_history_entry",
    "friendly_error",
    "line_has_continuation",
    "new_shell_state",
    "print_commandlets",
    "print_events",
    "print_history",
    "print_plugin_graph",
    "print_triggers",
    "process_framework_requests",
    "read_logical_input",
    "record_command_history",
    "redact_history_command",
    "remove_line_continuation",
    "render_prompt",
    "repl",
    "run_commandlet_remainder",
    "run_remainder",
    "set_prompt_pattern",
    "shutdown_runner",
    "split_command_sequence",
]
