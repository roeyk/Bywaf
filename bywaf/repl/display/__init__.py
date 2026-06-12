"""REPL display facade.

Re-exports focused display helpers from the display package so command handlers
and compatibility imports have one stable import path.

Used by:
- repl.commands and repl.shell: import operator-facing render helpers.
- bywaf.repl: preserve older package-level exports."""

from __future__ import annotations

from .catalog import (
    page_generated_text,
    print_commandlets,
    print_plugin_graph,
    print_plugins,
    print_topics,
    print_triggers,
    render_commandlets,
)
from .detail import print_event_info, print_run_variables
from .events import format_event, friendly_error, print_events
from .help import print_help
from .history import format_history_entry, print_history
from .runtime import print_info, print_job, print_jobs, print_runs
from .variables import display_expansion_preview, display_var_value, format_var_assignment, subject_text

# Stable display facade exports. REPL command modules import from here so
# concrete display helpers can move between focused modules without changing
# every command handler.
__all__ = [
    "display_expansion_preview",
    "display_var_value",
    "format_event",
    "format_history_entry",
    "format_var_assignment",
    "friendly_error",
    "page_generated_text",
    "print_commandlets",
    "print_event_info",
    "print_events",
    "print_help",
    "print_history",
    "print_info",
    "print_job",
    "print_plugin_graph",
    "print_jobs",
    "print_plugins",
    "print_run_variables",
    "print_runs",
    "print_topics",
    "print_triggers",
    "render_commandlets",
    "subject_text",
]
