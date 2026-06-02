"""Manifest validation helpers for plugin catalog generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def catalog_event_schema_entries(manifest_data: dict[str, Any], manifest_path: Path) -> list[dict[str, Any]]:
    """Return event schema metadata declared by one plugin sidecar manifest."""
    schema_rows = manifest_data.get("event_schemas", [])
    if not isinstance(schema_rows, list):
        raise ValueError(f"{manifest_path} event_schemas must be a list")
    rows: list[dict[str, Any]] = []
    for index, schema in enumerate(schema_rows, start=1):
        if not isinstance(schema, dict):
            raise ValueError(f"{manifest_path} event_schemas entry {index} must be a table")
        context = f"event_schemas entry {index}"
        field_rows = schema.get("fields", [])
        if not isinstance(field_rows, list):
            raise ValueError(f"{manifest_path} {context}.fields must be a list")
        rows.append(
            {
                "topic": required_string(schema, "topic", manifest_path, context),
                "version": optional_string(schema, "version", manifest_path, context, default="1"),
                "summary": optional_string(schema, "summary", manifest_path, context, default=""),
                "notes": list(string_list_value(schema, "notes", manifest_path, context)),
                "fields": catalog_event_schema_field_entries(field_rows, manifest_path, context),
            }
        )
    return rows


def catalog_event_schema_field_entries(
    field_rows: list[Any],
    manifest_path: Path,
    schema_context: str,
) -> list[dict[str, Any]]:
    """Return strict event schema field metadata rows."""
    rows: list[dict[str, Any]] = []
    for index, field in enumerate(field_rows, start=1):
        if not isinstance(field, dict):
            raise ValueError(f"{manifest_path} {schema_context}.fields entry {index} must be a table")
        context = f"{schema_context}.fields entry {index}"
        rows.append(
            {
                "name": required_string(field, "name", manifest_path, context),
                "type": optional_string(field, "type", manifest_path, context, default="any"),
                "required": bool_value(field, "required", manifest_path, context),
                "description": optional_string(field, "description", manifest_path, context, default=""),
                "allowed": list(string_list_value(field, "allowed", manifest_path, context)),
            }
        )
    return rows


def required_string(data: dict[str, Any], key: str, source: Path, context: str) -> str:
    """Return a required non-empty string metadata field."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def optional_string(
    data: dict[str, Any],
    key: str,
    source: Path,
    context: str,
    *,
    default: str | None = None,
) -> str | None:
    """Return an optional string metadata field."""
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def bool_value(data: dict[str, Any], key: str, source: Path, context: str, *, default: bool = False) -> bool:
    """Return an optional boolean metadata field."""
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{source} {context}.{key} must be true or false")
    return value


def string_list_value(data: dict[str, Any], key: str, source: Path, context: str) -> tuple[str, ...]:
    """Return an optional list containing only non-empty strings."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.{key} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source} {context}.{key} entry {index} must be a string")
    return tuple(value)


def table_value(data: dict[str, Any], key: str) -> dict[str, Any]:
    """Return one TOML table."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"[{key}] must be a table")
    return value
