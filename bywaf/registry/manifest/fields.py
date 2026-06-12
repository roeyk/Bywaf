"""Low-level plugin manifest field parsers.

Used by:
- plugin registry loading, manifest validation, plugin graph display, and
  plugin-check diagnostics.
- tests that assert manifest and dependency behavior.
"""

from __future__ import annotations

import re
from typing import Any

from ...specs import ArgumentSpec, CompletionSpec, OptionSpec

from ..compat import REQUIREMENT_RE

# Plugin sidecar versions are SemVer-like but intentionally not parsed as full
# packaging.version.Version objects; manifests only need a stable compatibility
# string for check/load diagnostics.
SEMVERISH_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def require_known_keys(data: dict[str, Any], allowed: set[str], source: str, context: str) -> None:
    """Reject unsupported manifest keys in one parsed TOML table."""
    # Fail closed on typos. A misspelled manifest key is usually a security or
    # capability declaration bug, not harmless extra metadata.
    unknown = sorted(str(key) for key in data.keys() if key not in allowed)
    if unknown:
        allowed_text = ", ".join(sorted(allowed))
        unknown_text = ", ".join(unknown)
        raise ValueError(f"{source} {context} has unknown key(s): {unknown_text}; allowed keys: {allowed_text}")


def validate_version_string(value: str, source: str, context: str) -> None:
    """Validate a SemVer-like plugin version string."""
    if not SEMVERISH_RE.match(value):
        raise ValueError(f"{source} {context} must be SemVer-like, for example 0.1.0")

def validate_requires_bywaf(value: str, source: str, context: str) -> None:
    """Validate a simple one-clause framework version requirement."""
    if not REQUIREMENT_RE.match(value.strip()):
        raise ValueError(f"{source} {context} must look like >=0.13.0")

def option_rows_field(data: dict[str, Any], source: str, context: str) -> tuple[OptionSpec, ...]:
    """Parse optional commandlet option metadata rows."""
    value = data.get("options", ())
    if value in (None, ()):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.options must be a list")
    # Include the row number in nested context strings so plugin_check can
    # point authors at the exact malformed option.
    return tuple(option_row_field(row, source, f"{context}.options entry {index}") for index, row in enumerate(value, start=1))

def option_row_field(row: Any, source: str, context: str) -> OptionSpec:
    """Parse one manifest commandlet option row."""
    if not isinstance(row, dict):
        raise ValueError(f"{source} {context} must be a table")
    require_known_keys(row, {"name", "description", "default", "choices", "completion", "secret", "type"}, source, context)
    # The manifest type names mirror CommandSpec option metadata. They are not
    # arbitrary JSON-schema types.
    value_type = optional_string_field(row, "type", source, context, default="str") or "str"
    if value_type not in {"str", "int", "optional-int", "float", "bool"}:
        raise ValueError(f"{source} {context}.type must be one of: str, int, optional-int, float, bool")
    completion = optional_string_field(row, "completion", source, context)
    return OptionSpec(
        name=string_field(row, "name", source, context),
        description=optional_string_field(row, "description", source, context, default="") or "",
        default=manifest_default_to_string(row.get("default")),
        choices=string_list_field(row, "choices", source, context),
        completion=CompletionSpec(completion or "none"),
        secret=bool_field(row, "secret", source, context),
        value_type=value_type,
    )

def argument_rows_field(data: dict[str, Any], source: str, context: str) -> tuple[ArgumentSpec, ...]:
    """Parse optional commandlet argument metadata rows."""
    value = data.get("arguments", ())
    if value in (None, ()):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.arguments must be a list")
    # Arguments are parsed separately from options because their required-ness
    # is derived from nargs rather than a boolean manifest field.
    return tuple(argument_row_field(row, source, f"{context}.arguments entry {index}") for index, row in enumerate(value, start=1))

def argument_row_field(row: Any, source: str, context: str) -> ArgumentSpec:
    """Parse one manifest commandlet argument row."""
    if not isinstance(row, dict):
        raise ValueError(f"{source} {context} must be a table")
    require_known_keys(row, {"name", "description", "nargs", "completion"}, source, context)
    nargs = optional_string_field(row, "nargs", source, context, default="") or ""
    completion = optional_string_field(row, "completion", source, context)
    # nargs follows argparse conventions: optional and variadic args are not
    # marked required in the commandlet metadata exposed to completion/docs.
    return ArgumentSpec(
        name=string_field(row, "name", source, context),
        description=optional_string_field(row, "description", source, context, default="") or "",
        required=nargs not in {"?", "*"},
        completion=CompletionSpec(completion or "none"),
    )

def string_field(data: dict[str, Any], key: str, source: str, context: str) -> str:
    """Return a required string field."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source} {context} requires {key}")
    return value

def optional_string_field(
    data: dict[str, Any],
    key: str,
    source: str,
    context: str,
    *,
    default: str | None = None,
) -> str | None:
    """Return an optional string manifest field."""
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value

def manifest_default_to_string(value: Any) -> str | None:
    """Normalize manifest defaults into CommandSpec string metadata."""
    if value is None:
        return None
    if isinstance(value, bool):
        # CommandSpec stores defaults as display/completion metadata, so TOML
        # booleans are normalized to lowercase strings.
        return "true" if value else "false"
    return str(value)

def table_value(data: dict[str, Any], key: str, source: str) -> dict[str, Any]:
    """Return one TOML table from a manifest."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{source} [{key}] must be a table")
    return value

def bool_field(data: dict[str, Any], key: str, source: str, context: str = "plugin") -> bool:
    """Return a boolean manifest field."""
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{source} {context}.{key} must be true or false")
    return value

def list_field(data: dict[str, Any], key: str, source: str) -> list[Any]:
    """Return a list manifest field."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} plugin.{key} must be a list")
    return value

def string_list_field(data: dict[str, Any], key: str, source: str, context: str) -> tuple[str, ...]:
    """Return an optional list field that must contain only non-empty strings."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.{key} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source} {context}.{key} entry {index} must be a string")
    return tuple(value)

def database_actions_field(data: dict[str, Any], source: str, context: str) -> tuple[str, ...]:
    """Return commandlet database action metadata from list/string/booleans."""
    direct = data.get("database_actions")
    if direct is not None:
        # Newer manifests may declare database_actions directly as a list or
        # comma-separated string, matching decorator metadata.
        if isinstance(direct, str):
            items = [item.strip() for item in direct.split(",") if item.strip()]
        elif isinstance(direct, list):
            items = direct
        else:
            raise ValueError(f"{source} {context}.database_actions must be a string or list")
        return normalize_database_actions(items, source, f"{context}.database_actions")
    database = data.get("database", {})
    if database in ({}, None):
        return ()
    if not isinstance(database, dict):
        raise ValueError(f"{source} {context}.database must be a table")
    actions = database.get("actions", {})
    if not isinstance(actions, dict):
        raise ValueError(f"{source} {context}.database.actions must be a table")
    selected: list[str] = []
    # Legacy/author-friendly TOML sidecars can use
    # database.actions.{view,write,manage}=true booleans. Normalize them to the
    # same ordered tuple as the direct form above.
    for action in ("view", "write", "manage"):
        enabled = actions.get(action, False)
        if not isinstance(enabled, bool):
            raise ValueError(f"{source} {context}.database.actions.{action} must be true or false")
        if enabled:
            selected.append(action)
    return tuple(selected)

def normalize_database_actions(items: list[Any], source: str, context: str) -> tuple[str, ...]:
    """Validate and order database action names."""
    allowed = ("view", "write", "manage")
    selected: set[str] = set()
    for index, item in enumerate(items, start=1):
        if not isinstance(item, str):
            raise ValueError(f"{source} {context} entry {index} must be a string")
        if item not in allowed:
            raise ValueError(f"{source} {context} entry {index} must be one of: {', '.join(allowed)}")
        selected.add(item)
    # Preserve the framework's privilege ordering instead of caller input order
    # so manifests and decorators compare deterministically.
    return tuple(action for action in allowed if action in selected)
