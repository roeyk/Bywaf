"""REPL preference command handlers.

Used by: `repl.command.resources` as the implementation of the `pref`
built-in.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ...runner import Runner
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
from ..themes import theme_names

if TYPE_CHECKING:
    from ..state import ShellState


def handle_pref_command(runner: Runner, state: ShellState, rest: str | None, line: str) -> str | None:
    """Manage user-local preferences that should follow the operator.

    Called by: the REPL built-in command dispatcher for `pref`.
    """
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
    """Print persisted preferences, or active preference-like values.

    Called by: `handle_pref_command()` for `pref` and `pref list`.
    """
    values = load_preferences(path)
    if not values:
        values = preference_snapshot(runner, state, {})
    for key, value in sorted(values.items()):
        print(format_preference_assignment(key, value))


def preference_assignment(tokens: Sequence[str]) -> tuple[str, str]:
    """Return the first non-file `key=value` preference assignment.

    Called by: `handle_pref_command()` for `pref set`.
    """
    for token in tokens:
        if token.startswith("file="):
            continue
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        return key, value
    raise ValueError("usage: pref set key=value [file=<path>]")


def preference_key_argument(tokens: Sequence[str]) -> str:
    """Return the first non-selector token as a preference key.

    Called by: `handle_pref_command()` for `pref unset`.
    """
    for token in tokens:
        if token.startswith("file="):
            continue
        if token:
            return token
    raise ValueError("usage: pref unset key [file=<path>]")


def preference_prompt_pattern(tokens: Sequence[str]) -> str:
    """Return prompt pattern text from `pref prompt` args.

    Called by: `handle_pref_command()` for `pref prompt`.
    """
    pattern_tokens = [token for token in tokens if not token.startswith("file=")]
    pattern = " ".join(pattern_tokens)
    if not pattern:
        raise ValueError("usage: pref prompt <pattern> [file=<path>]")
    return pattern


def selector_value(tokens: Sequence[str], key: str) -> str | None:
    """Return selector value from `key=value` tokens.

    Called by: preference command parsing helpers.
    """
    prefix = f"{key}="
    for token in tokens:
        if token.startswith(prefix):
            return token.split("=", 1)[1]
    return None
