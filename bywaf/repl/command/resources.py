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
from ..display import print_history
from ..persistence import load_config, load_history, save_config, save_history
from ..preferences import (
    THEME_KEY,
    apply_preferences,
    format_preference_assignment,
    load_preferences,
    preference_snapshot,
    resolve_preferences_path,
    save_preferences,
    set_preference,
    unset_preference,
)
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


def handle_pref_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Manage user-local preferences that should follow the operator."""
    del line
    tokens = shlex.split(rest) if rest else []
    action = tokens[0] if tokens else "list"
    args = tokens[1:] if tokens else []
    file_value = selector_value(tokens, "file")
    path = resolve_preferences_path(file_value)
    theme_value = selector_value(tokens, "theme")
    if theme_value:
        set_preference(runner, state, path, THEME_KEY, theme_value)
        print(f"saved pref theme={theme_value}")
    elif action == "theme":
        print("themes: " + ", ".join(theme_names()))
    elif action == "list":
        print_preferences(runner, state, path)
    elif action == "load":
        values = load_preferences(path)
        apply_preferences(runner, state, values)
        print(f"loaded pref={path}")
    elif action == "save":
        values = preference_snapshot(runner, state, load_preferences(path))
        save_preferences(path, values)
        print(f"saved pref={path}")
    elif action == "set":
        key, value = preference_assignment(args)
        set_preference(runner, state, path, key, value)
        print(f"saved pref {key}={value}")
    elif action == "unset":
        key = preference_key_argument(args)
        removed = unset_preference(runner, state, path, key)
        print(f"unset pref {key}" if removed else f"pref not set: {key}")
    elif action == "prompt":
        pattern = preference_prompt_pattern(args)
        set_preference(runner, state, path, "prompt.pattern", pattern)
        print(f"saved pref prompt={pattern}")
    else:
        print("usage: pref [list|load|save] [file=<path>], pref set key=value [file=<path>], pref unset key [file=<path>], pref theme=<preset> [file=<path>], or pref prompt <pattern> [file=<path>]")
    return None


def print_preferences(runner: Runner, state: ShellState, path: Path) -> None:
    """Print persisted preferences, or active preference-like values."""
    values = load_preferences(path)
    if not values:
        values = preference_snapshot(runner, state, {})
    for key, value in sorted(values.items()):
        print(format_preference_assignment(key, value))


def preference_assignment(tokens: Sequence[str]) -> tuple[str, str]:
    """Return the first non-file `key=value` preference assignment."""
    for token in tokens:
        if token.startswith("file="):
            continue
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        return key, value
    raise ValueError("usage: pref set key=value [file=<path>]")


def preference_key_argument(tokens: Sequence[str]) -> str:
    """Return the first non-selector token as a preference key."""
    for token in tokens:
        if token.startswith("file="):
            continue
        if token:
            return token
    raise ValueError("usage: pref unset key [file=<path>]")


def preference_prompt_pattern(tokens: Sequence[str]) -> str:
    """Return prompt pattern text from `pref prompt` args."""
    pattern_tokens = [token for token in tokens if not token.startswith("file=")]
    pattern = " ".join(pattern_tokens)
    if not pattern:
        raise ValueError("usage: pref prompt <pattern> [file=<path>]")
    return pattern


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


def selector_value(tokens: Sequence[str], key: str) -> str | None:
    """Return selector value from `key=value` tokens."""
    prefix = f"{key}="
    for token in tokens:
        if token.startswith(prefix):
            return token.split("=", 1)[1]
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
