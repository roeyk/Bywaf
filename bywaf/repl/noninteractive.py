"""Non-interactive REPL execution helpers.

Used by:
- `bywaf.app`: runs `bywaf exec ...` and direct commandlet invocations.
- `repl.shell`: re-exports these helpers for the stable REPL import surface.
"""

from __future__ import annotations

from ..framework_requests import process_framework_requests
from ..plugins.network.nmap.backend import NmapScanError, NmapUnavailableError
from ..runner import Runner
from .commands import execute_shell_command, visible_commandlet_events
from .display import friendly_error
from .parsing import command_from_remainder, split_command_sequence
from .state import new_shell_state


def execute_and_print(runner: Runner, command: str) -> int:
    """Execute one command line for top-level `bywaf exec` callers.

    Called by: CLI app dispatch for explicit `exec` mode.
    """
    return execute_shell_command(runner, command)


def execute_commandlet_and_print(runner: Runner, command: str) -> int:
    """Execute one commandlet line for direct non-interactive CLI callers.

    Called by: CLI app dispatch when the first token is a commandlet.
    """
    try:
        state = new_shell_state(runner)
        events = runner.execute(command)
        process_framework_requests(runner, state)
        from .display import print_events

        # Direct commandlet invocation should behave like a one-shot REPL line:
        # execute, process framework render requests, then print visible events.
        print_events(visible_commandlet_events(events), runner)
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


def run_remainder(runner: Runner, tokens: list[str]) -> int:
    """Validate and run the token remainder from `bywaf exec ...`.

    Called by: CLI app dispatch after parsing global options.
    """
    try:
        command = command_from_remainder(tokens)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    return execute_and_print(runner, command)


def run_commandlet_remainder(runner: Runner, tokens: list[str]) -> int:
    """Validate and run direct non-interactive commandlet arguments.

    Called by: CLI app dispatch for direct commandlet mode.
    """
    try:
        command = command_from_remainder(tokens)
    except ValueError:
        print("error: commandlet invocation requires a command")
        return 1
    status = 0
    for one_command in split_command_sequence(command) or [command]:
        # Preserve shell-style command chaining: stop at the first failing
        # commandlet so scripts see a meaningful exit status.
        status = execute_commandlet_and_print(runner, one_command)
        if status != 0:
            return status
    return status
