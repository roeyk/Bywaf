"""Shared event payload schemas.

Provides lightweight topic schemas for framework-known event topics. These
event schemas make event topics usable as stable interoperability interfaces while
keeping plugin-private topics free-form.

Used by:
- plugin authors and tests: validate payloads for shared topics.
- documentation and future views: describe which fields are safe to depend on.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import fields, is_dataclass
from typing import Any, ClassVar, Self, TypeVar

from .catalog import EVENT_SCHEMAS
from .defs import FIELD_TYPES, EventSchema, FieldSchema
from .registry import event_schema as event_schema
from .registry import field_value_matches as field_value_matches
from .registry import plugin_event_schemas as plugin_event_schemas
from .registry import register_event_schema as register_event_schema
from .registry import register_event_schemas as register_event_schemas
from .registry import unregister_event_schema as unregister_event_schema
from .registry import validate_event_payload as validate_event_payload

T = TypeVar("T")

__all__ = [
    "EVENT_SCHEMAS",
    "FIELD_TYPES",
    "EventSchema",
    "EventSchemaObject",
    "FieldSchema",
    "accepted_factory_fields",
    "event_schema",
    "field_value_matches",
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


class EventSchemaObject:
    """Base class for plugin-owned objects backed by a shared event schema."""

    __topic__: ClassVar[str]

    @classmethod
    def from_event(cls, event: Any) -> Self:
        """Deserialize a shared-schema event into this object type."""
        topic = cls.schema_topic()
        if event_schema(topic) is not None:
            return schema_object(event, topic, cls)
        payload = schema_payload(event, topic)
        values = {name: value for name, value in payload.items()}
        accepted = accepted_factory_fields(cls)
        if accepted is not None:
            values = {name: value for name, value in values.items() if name in accepted}
        return cls(**values)

    @classmethod
    def from_events(cls, events: Iterable[Any]) -> tuple[Self, ...]:
        """Deserialize matching events into schema objects."""
        topic = cls.schema_topic()
        return tuple(cls.from_event(event) for event in events if getattr(event, "topic", None) == topic)

    @classmethod
    def schema_topic(cls) -> str:
        """Return the shared event topic this object represents."""
        topic = getattr(cls, "__topic__", "")
        if not topic:
            raise ValueError(f"{cls.__name__} must define __topic__")
        return topic

    def to_payload(self) -> dict[str, Any]:
        """Serialize this object to its shared event schema payload."""
        topic = self.schema_topic()
        schema = event_schema(topic)
        if schema is None:
            payload = object_payload_fields(self)
        else:
            payload = {
                field.name: getattr(self, field.name)
                for field in schema.fields
                if hasattr(self, field.name) and getattr(self, field.name) is not None
            }
            errors = validate_event_payload(topic, payload)
            if errors:
                raise ValueError("; ".join(errors))
        return payload


def schema_payload(event: Any, topic: str) -> Mapping[str, Any]:
    """Return a validated shared-schema payload from an event.

    Plugin authors can use this directly or through ``schema_object`` before
    constructing their own typed domain objects from shared event facts.
    """
    event_topic = getattr(event, "topic", None)
    if event_topic != topic:
        raise ValueError(f"expected {topic} event, got {event_topic}")
    payload = getattr(event, "payload", None)
    if not isinstance(payload, Mapping):
        raise ValueError(f"{topic} payload must be a mapping")
    if event_schema(topic) is None:
        return payload
    errors = validate_event_payload(topic, payload)
    if errors:
        raise ValueError("; ".join(errors))
    return payload


def schema_object(event: Any, topic: str, factory: Callable[..., T]) -> T:
    """Deserialize a shared-schema event into a schema object.

    The factory must accept the schema fields as keyword arguments, which
    makes dataclasses and small typed constructors work naturally.
    """
    schema = event_schema(topic)
    if schema is None:
        raise ValueError(f"unknown shared event schema: {topic}")
    payload = schema_payload(event, topic)
    fields = {field.name: payload[field.name] for field in schema.fields if field.name in payload}
    accepted = accepted_factory_fields(factory)
    if accepted is not None:
        fields = {name: value for name, value in fields.items() if name in accepted}
    return factory(**fields)


def schema_objects(events: Iterable[Any], factory: Callable[..., T]) -> tuple[T, ...]:
    """Deserialize matching events into schema objects using a topic-aware factory."""
    topic = getattr(factory, "__topic__", "")
    if not topic and hasattr(factory, "schema_topic"):
        topic = str(factory.schema_topic())  # type: ignore[attr-defined]
    if not topic:
        raise ValueError("schema object factory must define __topic__ or schema_topic()")
    return tuple(schema_object(event, topic, factory) for event in events if getattr(event, "topic", None) == topic)


def accepted_factory_fields(factory: Callable[..., Any]) -> set[str] | None:
    """Return keyword names accepted by a factory, or None for arbitrary kwargs."""
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):
        return None
    names: set[str] = set()
    for name, parameter in signature.parameters.items():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            return None
        if parameter.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
            names.add(name)
    return names


def object_payload_fields(obj: object) -> dict[str, Any]:
    """Return public dataclass/object fields suitable for plugin-owned payloads."""
    if is_dataclass(obj):
        return {
            field.name: getattr(obj, field.name)
            for field in fields(obj)
            if not field.name.startswith("_") and getattr(obj, field.name) is not None
        }
    return {
        name: value
        for name, value in vars(obj).items()
        if not name.startswith("_") and value is not None
    }
