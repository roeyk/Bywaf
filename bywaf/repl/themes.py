"""Display theme loading and bundled presets.

Provides small helpers that apply named or file-backed style variables to the
current REPL session.

Used by:
- REPL config command: load theme presets and user-authored theme files.
- completion/docs/tests: expose known theme names and expected variables."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..runner import Runner
from ..toml_support import load_data_text


THEME_PRESETS: dict[str, dict[str, str]] = {
    "default": {},
    "classic": {
        "display.vars.color": "auto",
        "display.vars.name-color": "cyan",
        "display.vars.value-color": "green",
        "display.events.color": "auto",
        "display.events.key-color": "green",
        "display.history.color": "auto",
        "display.history.timestamp-color": "green",
        "display.help.color": "auto",
        "display.help.command-color": "green",
        "display/style.comment": "dim color245",
        "display/style.string": "bold yellow",
        "display/style.value": "green",
        "display/style.variable": "cyan",
        "display/style.host": "bold green",
        "display/style.port": "yellow",
        "display/style.protocol": "cyan",
        "display/style.table.header": "bold color39",
        "display/style.table.index": "bold color245",
        "display/style.report.heading": "bold color39",
        "display/style.report.section": "bold white",
        "display/style.report.label": "bold color245",
        "display/style.finding.severity_class.emergency": "bold white bg-ansi:52",
        "display/style.finding.severity_class.urgent": "bold red",
        "display/style.finding.severity_class.review": "yellow",
        "display/style.finding.severity_class.advisory": "color39",
        "display/style.finding.severity_class.informational": "color245",
        "display/style.finding.severity.critical": "bold red",
        "display/style.finding.severity.high": "red",
        "display/style.finding.title": "bold white",
    },
    "mono": {
        "display.vars.color": "never",
        "display.events.color": "never",
        "display.history.color": "never",
        "display.help.color": "never",
        "display/style.comment": "",
        "display/style.string": "",
        "display/style.value": "",
        "display/style.variable": "",
        "display/style.table.header": "",
        "display/style.table.body": "",
        "display/style.table.index": "",
        "display/style.report.heading": "",
        "display/style.report.section": "",
        "display/style.report.label": "",
        "display/style.finding.severity_class.emergency": "",
        "display/style.finding.severity_class.urgent": "",
        "display/style.finding.severity_class.review": "",
        "display/style.finding.severity_class.advisory": "",
        "display/style.finding.severity_class.informational": "",
    },
}


def theme_names() -> tuple[str, ...]:
    """Return bundled theme names."""
    return tuple(sorted(THEME_PRESETS))


def apply_theme_name(runner: Runner, name: str) -> None:
    """Apply one bundled theme preset to the current session variables."""
    try:
        values = THEME_PRESETS[name]
    except KeyError as exc:
        raise ValueError(f"unknown theme: {name}") from exc
    apply_theme_values(runner, values)


def apply_theme_file(runner: Runner, path: Path) -> None:
    """Apply display variables from a user-authored JSON/TOML theme file."""
    data = load_data_text(path.read_text(encoding="utf-8"), suffix=path.suffix, label=str(path))
    values = data.get("variables", data)
    if not isinstance(values, dict):
        raise ValueError(f"{path} theme variables must be an object/table")
    apply_theme_values(runner, flatten_theme_values(values))


def flatten_theme_values(values: dict[str, Any]) -> dict[str, str]:
    """Return flat display variable assignments from theme data."""
    flattened: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(value, dict):
            flattened[str(key)] = str(value)
            continue
        for child_key, child_value in flatten_theme_values(value).items():
            flattened[f"{key}.{child_key}"] = child_value
    return flattened


def apply_theme_values(runner: Runner, values: dict[str, str]) -> None:
    """Apply only display-related variables from a theme mapping."""
    for key, value in values.items():
        if not is_theme_variable(key):
            raise ValueError(f"theme variable must start with display. or display/style.: {key}")
        runner.registry.varstore.set(key, value)


def is_theme_variable(key: str) -> bool:
    """Return whether a variable belongs in a display theme."""
    return key.startswith("display.") or key.startswith("display/style.")
