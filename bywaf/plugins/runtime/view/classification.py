"""Classify runtime commands as read-only operator views.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from collections.abc import Sequence

from bywaf.runtime.display import args_from_command_line, commandlet_from_command_line

# Runtime view detection affects follow-up commands, cursor handling, and shell
# completion. is_view_commandlet() uses this base set for commandlets whose
# default action is read-only.
VIEW_COMMANDLETS = {
    "audit",
    "finding_report",
    "job",
    "pipeline",
    "ports",
    "report",
    "result",
    "results",
    "search",
    "step",
}
# Some runtime commandlets have read-only subcommands that should still count as
# views. is_view_commandlet() uses this classification table for those actions.
VIEW_ACTIONS = {
    "artifact": {"list", "search", "show", "verify"},
    "bundle": {"list", "show", "verify"},
    "key": {"list", "show", "test"},
}
# Mutating subcommands are not runtime views even when they appear on otherwise
# view-oriented commandlets. is_view_commandlet() checks this classification
# table first.
MUTATING_ACTIONS = {
    "note": {"add"},
    "report": {"accept", "defer", "reject"},
}


def is_view_command_line(command_line: str) -> bool:
    """Return whether a recorded command line is an operator view command."""
    commandlet = commandlet_from_command_line(command_line)
    args = args_from_command_line(command_line)
    return is_view_commandlet(commandlet, args=args)


def is_view_commandlet(commandlet: str, *, args: Sequence[str] = ()) -> bool:
    """Return whether a commandlet name is a view-style command."""
    name = commandlet.strip()
    short_name = name.rsplit("/", 1)[-1]
    if short_name in MUTATING_ACTIONS:
        return not args or args[0] not in MUTATING_ACTIONS[short_name]
    if short_name in VIEW_ACTIONS:
        return bool(args) and args[0] in VIEW_ACTIONS[short_name]
    return name in VIEW_COMMANDLETS or short_name in VIEW_COMMANDLETS
