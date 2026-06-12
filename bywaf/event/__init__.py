"""Event subsystem public surface.

Provides the event value object, shared event schemas, schema-backed objects,
and payload-filter helpers used by stores, plugins, reports, and REPL views.

Used by:
- EventStore, schema validation, and runtime/report display helpers.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""

from .model import Event
from .schemas import (
    EVENT_SCHEMAS,
    EventSchema,
    EventSchemaObject,
    FieldSchema,
    accepted_factory_fields,
    event_schema,
    object_payload_fields,
    plugin_event_schemas,
    register_event_schema,
    register_event_schemas,
    schema_object,
    schema_objects,
    schema_payload,
    unregister_event_schema,
    validate_event_payload,
)

__all__ = [
    "EVENT_SCHEMAS",
    "Event",
    "EventSchema",
    "EventSchemaObject",
    "FieldSchema",
    "accepted_factory_fields",
    "event_schema",
    "object_payload_fields",
    "plugin_event_schemas",
    "register_event_schema",
    "register_event_schemas",
    "schema_object",
    "schema_objects",
    "schema_payload",
    "unregister_event_schema",
    "validate_event_payload",
]
