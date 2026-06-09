"""REPL resource, preference, history, and project commands.

Provides built-ins that read or write operator resources such as history,
config, preferences, scripts, and project state.

Used by:
- bywaf.repl.commands: registers resource-oriented built-ins.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ...runner import Runner
from .pref import handle_pref_command, selector_value  # noqa: F401 - re-exported for repl.commands
from ..display import print_history
from ..persistence import load_config, load_history, save_config, save_history
from ..resources import (
    DEFAULT_CONFIG,
    DEFAULT_HISTORY,
    DEFAULT_SCRIPT_DIR,
    dispatch_project_command,
    print_project_info,
    resolve_resource_path,
)
from ..scripts import run_script
from ..themes import apply_theme_file, apply_theme_name, theme_names

if TYPE_CHECKING:
    from ..state import ShellState


def handle_history_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Print command history."""
    del line
    if rest and history_resource_command(runner, state, shlex.split(rest)):
        return None
    selectors = parse_history_selectors(shlex.split(rest)) if rest else None
    print_history(state.session_history, selectors, runner)
    return None


def history_resource_command(runner: Runner, state: ShellState, tokens: list[str]) -> bool:
    """Handle `history load/save` forms; return whether an action ran."""
    action = tokens[0] if tokens else ""
    if action not in {"load", "save"}:
        return False
    file_value = selector_value(tokens[1:], "file")
    path = resolve_resource_path(file_value or "", Path("."), DEFAULT_HISTORY)
    if action == "load":
        del runner
        load_history(state, path)
    else:
        save_history(state, path, encrypt="--encrypt" in tokens[1:])
    return True


def handle_config_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load or save framework configuration."""
    del state, line
    tokens = shlex.split(rest) if rest else []
    if not tokens:
        print("usage: config load file=<path>, config save file=<path> [--encrypt], config theme name=<preset>, or config theme file=<path>")
        return None
    action = tokens[0]
    if action == "theme":
        apply_theme_command(runner, tokens[1:])
        return None
    file_value = selector_value(tokens[1:], "file")
    path = resolve_resource_path(file_value or "", Path("."), DEFAULT_CONFIG)
    if action == "load":
        load_config(runner, path)
    elif action == "save":
        save_config(runner, path, encrypt="--encrypt" in tokens[1:])
    else:
        print("usage: config load file=<path>, config save file=<path> [--encrypt], config theme name=<preset>, or config theme file=<path>")
    return None


def apply_theme_command(runner: Runner, tokens: list[str]) -> None:
    """Apply a named or file-backed syntax/display theme."""
    if not tokens:
        print("themes: " + ", ".join(theme_names()))
        return
    name = selector_value(tokens, "name")
    file_value = selector_value(tokens, "file")
    if bool(name) == bool(file_value):
        raise ValueError("usage: config theme name=<preset> or config theme file=<path>")
    if name:
        apply_theme_name(runner, name)
        print(f"loaded theme={name}")
        return
    assert file_value is not None
    path = resolve_resource_path(file_value, Path("."))
    apply_theme_file(runner, path)
    print(f"loaded theme={path}")


def handle_script_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Load/run or save REPL scripts."""
    del line
    tokens = shlex.split(rest) if rest else []
    if not tokens:
        print("usage: script load file=<path>, script save file=<path> [--encrypt]")
        return None
    action = tokens[0]
    file_value = selector_value(tokens[1:], "file")
    if action == "load":
        if not file_value:
            raise ValueError("usage: script load file=<path>")
        run_script(runner, resolve_script_load_path(file_value), state)
    elif action == "save":
        path = resolve_resource_path(file_value or "", Path("."), DEFAULT_HISTORY)
        save_history(state, path, encrypt="--encrypt" in tokens[1:])
    else:
        print("usage: script load file=<path>, script save file=<path> [--encrypt]")
    return None


def handle_project_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Show or dispatch project commands."""
    del line
    if rest is None:
        print_project_info(runner)
    else:
        dispatch_project_command(runner, state, shlex.split(rest))
    return None


def resolve_script_load_path(file_value: str) -> Path:
    """Resolve script loads from cwd first, then the project script directory."""
    direct = Path(file_value).expanduser()
    if direct.exists():
        return direct
    return resolve_resource_path(file_value, DEFAULT_SCRIPT_DIR)


def parse_history_selectors(tokens: Sequence[str]) -> dict[str, str]:
    """Parse `history since=... until=...` selector tokens."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        key, value = token.split("=", 1)
        if key not in {"since", "until"}:
            raise ValueError("history selectors must be since=<time> or until=<time>")
        if not value:
            raise ValueError(f"history {key}= requires a value")
        selectors[key] = value
    return selectors
