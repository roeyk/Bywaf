"""REPL package compatibility exports.

Provides the stable `bywaf.repl` import surface while implementation lives in
cohesive sibling modules such as shell, commands, display, and resources."""


from .display import display_var_value
from .display import format_event
from .display import format_history_entry_for_display
from .display import friendly_error
from .display import print_commandlets
from .display import print_events
from .display import print_history
from .display import print_triggers
from .shell import DEFAULT_HISTORY_TIMESTAMP_FORMAT
from .shell import HISTORY_TIMESTAMP_FORMAT_VAR
from .shell import ShellState
from .shell import build_input_reader
from .shell import command_from_remainder
from .shell import confirm_repl_exit
from .shell import dispatch_repl_line
from .shell import execute_and_print
from .shell import line_has_continuation
from .shell import new_shell_state
from .shell import process_framework_requests
from .shell import read_logical_input
from .shell import record_command_history
from .shell import redact_history_command
from .shell import remove_line_continuation
from .shell import render_prompt
from .shell import repl
from .shell import run_remainder
from .shell import shutdown_runner
from .shell import split_command_sequence
from .commands import set_prompt_pattern
