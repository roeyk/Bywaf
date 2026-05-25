"""TOML loading and dumping compatibility helpers.

Provides a small TOML interface that uses the available standard-library or
third-party TOML implementation while keeping callers isolated from that choice.

Used by:
- registry, resources, and signing tools: read plugin manifests and configs.
- tests: validate TOML-backed metadata behavior."""


from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any


def load_data_file(path: Path) -> dict[str, Any]:
    """Load a JSON or TOML mapping file."""
    return load_data_text(path.read_text(encoding="utf-8"), suffix=path.suffix, label=str(path))


def load_data_text(text: str, *, suffix: str, label: str = "data") -> dict[str, Any]:
    """Load a JSON or TOML mapping from text."""
    if suffix == ".toml":
        data: Any = tomllib.loads(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{label} must contain an object/table")
    return data


def dump_variables_toml(values: dict[str, Any]) -> str:
    """Serialize flat session variables as a human-editable TOML table."""
    lines = ["[variables]"]
    lines.extend(f"{toml_key(key)} = {toml_value(value)}" for key, value in sorted(values.items()))
    return "\n".join(lines) + "\n"


def toml_key(key: object) -> str:
    """Return a TOML quoted key so dotted variable names stay flat."""
    # Quoting is important: unquoted `a.b` would become a nested TOML table, but
    # Bywaf variables treat dots and slashes as literal scope syntax.
    return json.dumps(str(key))


def toml_value(value: Any) -> str:
    """Return a conservative TOML literal for simple user-authored values."""
    match value:
        case bool():
            return "true" if value else "false"
        case int() | float():
            return str(value)
        case _:
            return json.dumps(str(value))
