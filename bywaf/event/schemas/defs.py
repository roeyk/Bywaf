"""Core event schema data types.

These small immutable objects are used by the framework schema catalog,
plugin manifest parsing, runtime schema views, and plugin-check diagnostics.
The heavier registry and validation helpers live in `bywaf.event.schemas`.

Used by:
- EventStore, schema validation, and runtime/report display helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

FieldType = Literal["any", "bool", "dict", "int", "list", "number", "str"]
FIELD_TYPES: tuple[FieldType, ...] = ("any", "bool", "dict", "int", "list", "number", "str")


@dataclass(frozen=True, slots=True)
class FieldSchema:
    """One field in a shared event payload schema."""

    name: str
    field_type: FieldType = "any"
    required: bool = False
    description: str = ""
    allowed: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventSchema:
    """Payload schema for one shared event topic."""

    topic: str
    summary: str
    fields: tuple[FieldSchema, ...]
    notes: tuple[str, ...] = ()
    version: str = "1"

    @property
    def required_fields(self) -> tuple[str, ...]:
        """Return required payload field names."""
        return tuple(field.name for field in self.fields if field.required)
