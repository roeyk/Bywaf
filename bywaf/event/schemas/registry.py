"""Runtime event schema registry and payload validation.

Used by: event publication, plugin checks, runtime schema views, and
schema-object conversion helpers. Framework-owned schemas are immutable; loaded
plugins may register additional plugin-owned schemas at runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .catalog import EVENT_SCHEMAS
from .defs import EventSchema, FieldType

PLUGIN_EVENT_SCHEMAS: dict[str, EventSchema] = {}


def event_schema(topic: str) -> EventSchema | None:
    """Return the shared schema for a topic, if Bywaf or a loaded plugin defines one."""
    return EVENT_SCHEMAS.get(topic) or PLUGIN_EVENT_SCHEMAS.get(topic)


def register_event_schema(schema: EventSchema) -> None:
    """Register one plugin-owned event schema for runtime validation and views."""
    existing_framework_schema = EVENT_SCHEMAS.get(schema.topic)
    if existing_framework_schema is not None:
        if existing_framework_schema == schema:
            return
        raise ValueError(f"cannot override framework event schema: {schema.topic}")
    existing_plugin_schema = PLUGIN_EVENT_SCHEMAS.get(schema.topic)
    if existing_plugin_schema is not None and existing_plugin_schema != schema:
        raise ValueError(f"conflicting plugin event schema: {schema.topic}")
    PLUGIN_EVENT_SCHEMAS[schema.topic] = schema


def register_event_schemas(schemas: Iterable[EventSchema]) -> None:
    """Register plugin-owned event schemas."""
    for schema in schemas:
        register_event_schema(schema)


def unregister_event_schema(topic: str) -> None:
    """Remove one plugin-owned schema. Intended mainly for isolated tests."""
    PLUGIN_EVENT_SCHEMAS.pop(topic, None)


def plugin_event_schemas() -> Mapping[str, EventSchema]:
    """Return currently registered plugin-owned schemas."""
    return dict(PLUGIN_EVENT_SCHEMAS)


def validate_event_payload(topic: str, payload: Mapping[str, Any]) -> list[str]:
    """Return validation errors for a shared-topic payload.

    Plugin-private topics intentionally return no errors here. They may define
    their own sidecar schemas later without changing the framework registry.
    """
    schema = event_schema(topic)
    if schema is None:
        return []
    errors: list[str] = []
    for field in schema.fields:
        if field.name not in payload:
            if field.required:
                errors.append(f"{topic}.{field.name} is required")
            continue
        value = payload[field.name]
        if not field_value_matches(value, field.field_type):
            errors.append(f"{topic}.{field.name} must be {field.field_type}")
            continue
        if field.allowed and str(value) not in field.allowed:
            allowed = ", ".join(field.allowed)
            errors.append(f"{topic}.{field.name} must be one of: {allowed}")
    return errors


def field_value_matches(value: Any, field_type: FieldType) -> bool:
    """Return whether a value matches a schema field type."""
    if value is None or field_type == "any":
        return True
    if field_type == "bool":
        return isinstance(value, bool)
    if field_type == "dict":
        return isinstance(value, dict)
    if field_type == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type == "list":
        return isinstance(value, list)
    if field_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if field_type == "str":
        return isinstance(value, str)
    return False
