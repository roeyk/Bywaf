"""User-local preference persistence for the interactive shell.

Provides a small preferences layer for operator UX defaults that should follow
the user across projects without changing scan inputs or evidence.

Used by:
- REPL pref command: list, set, unset, load, save, and theme preferences.
- shell startup: apply the user preference file when it exists."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..runner import Runner
from ..toml_support import load_data_text, toml_key, toml_value
from .themes import apply_theme_name

if TYPE_CHECKING:
    from .state import ShellState


DEFAULT_PREFERENCES = Path("~/.bywaf/preferences.toml")
PREFERENCES_SECTION = "preferences"
PROMPT_PATTERN_KEY = "prompt.pattern"
THEME_KEY = "theme"

PREFERENCE_PREFIXES = (
    "completion.",
    "display.",
    "display/style.",
    "history.",
    "identity.",
    "mail.",
    "report.delivery.",
    "report.identity.",
)
PREFERENCE_KEYS = {
    PROMPT_PATTERN_KEY,
    THEME_KEY,
    "secret.input-mode",
}


def resolve_preferences_path(raw: str | None = None) -> Path:
    """Return the explicit or default preference file path."""
    return Path(raw).expanduser() if raw else DEFAULT_PREFERENCES.expanduser()


def load_preferences(path: Path) -> dict[str, str]:
    """Read a preferences TOML/JSON file as flat string values."""
    if not path.exists():
        return {}
    data = load_data_text(path.read_text(encoding="utf-8"), suffix=path.suffix, label=str(path))
    values = data.get(PREFERENCES_SECTION, data)
    if not isinstance(values, dict):
        raise ValueError(f"{path} preferences must be an object/table")
    flattened = flatten_preference_values(values)
    for key in flattened:
        validate_preference_key(key)
    return flattened


def ensure_preferences_file(path: Path) -> None:
    """Create an empty preferences file for first-run operator discovery."""
    if not path.exists():
        save_preferences(path, {})


def save_preferences(path: Path, values: dict[str, str]) -> None:
    """Persist preference values as a flat TOML table."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_preferences_toml(values), encoding="utf-8")


def dump_preferences_toml(values: dict[str, str]) -> str:
    """Serialize flat preference values as human-editable TOML."""
    lines = [f"[{PREFERENCES_SECTION}]"]
    lines.extend(f"{toml_key(key)} = {toml_value(value)}" for key, value in sorted(values.items()))
    return "\n".join(lines) + "\n"


def flatten_preference_values(values: dict[str, Any]) -> dict[str, str]:
    """Return flat preference assignments from nested TOML/JSON data."""
    flattened: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(value, dict):
            flattened[str(key)] = str(value)
            continue
        for child_key, child_value in flatten_preference_values(value).items():
            flattened[f"{key}.{child_key}"] = child_value
    return flattened


def apply_preferences(runner: Runner, state: ShellState, values: dict[str, str]) -> None:
    """Apply preference values to the current REPL session."""
    for key, value in values.items():
        validate_preference_key(key)
        if key == THEME_KEY:
            apply_theme_name(runner, value)
        elif key == PROMPT_PATTERN_KEY:
            state.prompt_pattern = value
        else:
            runner.registry.varstore.set(key, value)


def preference_snapshot(runner: Runner, state: ShellState, stored: dict[str, str] | None = None) -> dict[str, str]:
    """Return persistable preferences from stored values plus active UX vars."""
    values = dict(stored or {})
    for key, value in runner.registry.varstore.items():
        if is_preference_key(key):
            values[key] = str(value)
    values[PROMPT_PATTERN_KEY] = state.prompt_pattern
    return values


def set_preference(runner: Runner, state: ShellState, path: Path, key: str, value: str) -> None:
    """Set one preference, save it, and apply it immediately."""
    validate_preference_key(key)
    values = load_preferences(path)
    values[key] = value
    save_preferences(path, values)
    apply_preferences(runner, state, {key: value})


def unset_preference(runner: Runner, state: ShellState, path: Path, key: str) -> bool:
    """Remove one preference from disk and clear supported active values."""
    validate_preference_key(key)
    values = load_preferences(path)
    removed = key in values
    values.pop(key, None)
    save_preferences(path, values)
    if key == PROMPT_PATTERN_KEY:
        state.prompt_pattern = "$Y$M$D $h:$m:$s $Z%F> "
    elif key != THEME_KEY:
        runner.registry.varstore.values.pop(key, None)
    return removed


def is_preference_key(key: str) -> bool:
    """Return whether a key is allowed in user-local preferences."""
    return key in PREFERENCE_KEYS or key.startswith(PREFERENCE_PREFIXES)


def validate_preference_key(key: str) -> None:
    """Reject project or scanner variables from user-local preferences."""
    if not is_preference_key(key):
        raise ValueError(f"not a preference key: {key}")


def format_preference_assignment(key: str, value: str) -> str:
    """Return a stable preference assignment for list output."""
    return f"{key}={value}"


def preferences_json(values: dict[str, str]) -> str:
    """Return JSON text for tests and future API-style output."""
    return json.dumps(values, indent=2, sort_keys=True) + "\n"
