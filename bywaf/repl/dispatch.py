"""REPL line dispatch.

Provides built-in command routing and commandlet fallback execution without
depending on shell input orchestration.

Used by:
- repl.shell: dispatch interactive lines.
- repl.scripts: run commands loaded from script files.
"""

from __future__ import annotations

from ..plugins.network.nmap_backend import NmapScanError, NmapUnavailableError
from ..registry import PluginTrustError
from ..runner import Runner
from .commands import REPL_COMMAND_HANDLERS, execute_repl_commandlet
from .display import friendly_error
from .parsing import split_command_sequence, strip_inline_comment
from .state import ShellState


def dispatch_repl_line(runner: Runner, line: str, state: ShellState | None = None) -> str | None:
    """Dispatch one REPL line and keep errors user-facing.

    Built-ins are handled here; commandlets fall through to the generic runner
    so plugin commands such as `ls` are not hard-coded into the shell.
    """
    state = state or ShellState(framework_request_after_id=runner.events.latest_event_id())
    line = strip_inline_comment(line)
    if not line.strip():
        return None
    commands = split_command_sequence(line)
    if len(commands) > 1:
        # Semicolon sequencing is handled at the REPL layer, not by the
        # commandlet parser, so each command gets normal built-in dispatch.
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
        # This lookup uses REPL_COMMAND_HANDLERS, imported from commands.py, in
        # place of an if/elif ladder over built-in REPL command names.
        handler = REPL_COMMAND_HANDLERS.get(name)
        if handler is not None:
            return handler(runner, state, rest, line)
        if runner.registry.has_commandlet(name):
            execute_repl_commandlet(runner, state, line)
            return None
        print("error: unknown command or commandlet")
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
