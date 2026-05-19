"""Small TOML helpers for human-authored Bywaf configuration files."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any


def load_data_file(path: Path) -> dict[str, Any]:
    """Load a JSON or TOML mapping file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        data: Any = tomllib.loads(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain an object/table")
    return data


def dump_variables_toml(values: dict[str, Any]) -> str:
    """Serialize flat session variables as a human-editable TOML table."""
    lines = ["[variables]"]
    lines.extend(f"{toml_key(key)} = {toml_value(value)}" for key, value in sorted(values.items()))
    return "\n".join(lines) + "\n"


def toml_key(key: object) -> str:
    """Return a TOML quoted key so dotted variable names stay flat."""
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
