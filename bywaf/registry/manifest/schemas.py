"""Plugin manifest event-schema section parser.

Used by:
- plugin registry loading, manifest validation, plugin graph display, and
  plugin-check diagnostics.
- tests that assert manifest and dependency behavior.
"""

from __future__ import annotations

from typing import Any

from ...event.schemas import EVENT_SCHEMAS, FIELD_TYPES, EventSchema, FieldSchema

from .fields import bool_field, optional_string_field, require_known_keys, string_field, string_list_field


def parse_event_schema_rows(value: Any, source: str) -> tuple[EventSchema, ...]:
    """Parse optional plugin-owned event schema manifest entries."""
    if value in (None, []):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} event_schemas must be a list")
    schemas: list[EventSchema] = []
    topics: set[str] = set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} event_schemas entry {index} must be a table")
        context = f"event_schemas entry {index}"
        require_known_keys(row, {"topic", "version", "summary", "notes", "fields"}, source, context)
        topic = string_field(row, "topic", source, context)
        if topic in EVENT_SCHEMAS:
            raise ValueError(f"{source} {context}.topic is framework-owned: {topic}")
        if topic in topics:
            raise ValueError(f"{source} duplicate event schema: {topic}")
        topics.add(topic)
        summary = optional_string_field(row, "summary", source, context, default="") or ""
        fields = event_schema_fields(row.get("fields", []), source, context)
        if not fields:
            raise ValueError(f"{source} {context}.fields must declare at least one field")
        schemas.append(
            EventSchema(
                topic=topic,
                summary=summary,
                fields=fields,
                notes=string_list_field(row, "notes", source, context),
                version=optional_string_field(row, "version", source, context, default="1") or "1",
            )
        )
    return tuple(schemas)

def event_schema_fields(value: Any, source: str, context: str) -> tuple[FieldSchema, ...]:
    """Parse one event schema's field rows."""
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.fields must be a list")
    fields: list[FieldSchema] = []
    names: set[str] = set()
    for index, row in enumerate(value, start=1):
        field_context = f"{context}.fields entry {index}"
        if not isinstance(row, dict):
            raise ValueError(f"{source} {field_context} must be a table")
        require_known_keys(row, {"name", "type", "required", "description", "allowed"}, source, field_context)
        name = string_field(row, "name", source, field_context)
        if name in names:
            raise ValueError(f"{source} {context}.fields duplicate field: {name}")
        names.add(name)
        field_type = optional_string_field(row, "type", source, field_context, default="any") or "any"
        if field_type not in FIELD_TYPES:
            raise ValueError(f"{source} {field_context}.type must be one of: {', '.join(FIELD_TYPES)}")
        fields.append(
            FieldSchema(
                name=name,
                field_type=field_type,
                required=bool_field(row, "required", source, field_context),
                description=optional_string_field(row, "description", source, field_context, default="") or "",
                allowed=string_list_field(row, "allowed", source, field_context),
            )
        )
    return tuple(fields)
