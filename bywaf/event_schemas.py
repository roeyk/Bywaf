"""Shared event payload schemas.

Provides lightweight topic schemas for framework-known event topics. These
event schemas make event topics usable as stable interoperability interfaces while
keeping plugin-private topics free-form.

Used by:
- plugin authors and tests: validate payloads for shared topics.
- documentation and future views: describe which fields are safe to depend on.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, ClassVar, Literal, Self, TypeVar

FieldType = Literal["any", "bool", "dict", "int", "list", "number", "str"]
T = TypeVar("T")


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

    @property
    def required_fields(self) -> tuple[str, ...]:
        """Return required payload field names."""
        return tuple(field.name for field in self.fields if field.required)


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


EVENT_SCHEMAS: dict[str, EventSchema] = {
    "host.found": EventSchema(
        topic="host.found",
        summary="A host was observed alive or otherwise reachable.",
        fields=(
            FieldSchema("host", "str", True, "IP address or hostname used for follow-up work."),
            FieldSchema("ip", "str", False, "Concrete IP address when host is a DNS name or alias."),
            FieldSchema("name", "str", False, "Original DNS name or operator-provided name."),
            FieldSchema("status", "str", False, "Host state.", ("up", "reachable", "unknown")),
            FieldSchema("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "name.resolved": EventSchema(
        topic="name.resolved",
        summary="A name resolved to one or more concrete addresses.",
        fields=(
            FieldSchema("name", "str", True, "Original hostname."),
            FieldSchema("host", "str", True, "Resolved address."),
            FieldSchema("resolver", "str", False, "Resolver or backend that produced the mapping."),
        ),
    ),
    "port.open": EventSchema(
        topic="port.open",
        summary="A network port was observed open on a host.",
        fields=(
            FieldSchema("host", "str", True, "Host or address where the port is open."),
            FieldSchema("port", "int", True, "Numeric port."),
            FieldSchema("protocol", "str", True, "Transport protocol.", ("tcp", "udp")),
            FieldSchema("state", "str", False, "Observed port state.", ("open", "open|filtered")),
            FieldSchema("service", "str", False, "Best-known service name or probe label."),
            FieldSchema("reason", "str", False, "Scanner reason, such as syn-ack."),
            FieldSchema("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "http.endpoint": EventSchema(
        topic="http.endpoint",
        summary="A reachable HTTP or HTTPS endpoint.",
        fields=(
            FieldSchema("url", "str", True, "Canonical endpoint URL."),
            FieldSchema("host", "str", True, "Endpoint host."),
            FieldSchema("port", "int", True, "Endpoint port."),
            FieldSchema("scheme", "str", True, "HTTP scheme.", ("http", "https")),
            FieldSchema("status", "int", False, "HTTP status code."),
            FieldSchema("method", "str", False, "HTTP method used to probe the endpoint."),
            FieldSchema("server", "str", False, "Server header or equivalent banner."),
            FieldSchema("error", "str", False, "Probe error if endpoint metadata is partial."),
        ),
    ),
    "web.screenshotted_host": EventSchema(
        topic="web.screenshotted_host",
        summary="One host or endpoint has one or more screenshot artifacts.",
        fields=(
            FieldSchema("host", "str", True, "Endpoint host represented by the screenshots."),
            FieldSchema("urls", "list", True, "Endpoint URLs represented by the screenshots."),
            FieldSchema("screenshots", "list", True, "Screenshot artifact/file references."),
            FieldSchema("tool", "str", False, "Screenshot tool name."),
        ),
    ),
    "tcp.banner": EventSchema(
        topic="tcp.banner",
        summary="A TCP service banner or first response was captured.",
        fields=(
            FieldSchema("host", "str", True, "Host or address where the service responded."),
            FieldSchema("port", "int", True, "Numeric TCP port."),
            FieldSchema("protocol", "str", True, "Transport protocol.", ("tcp",)),
            FieldSchema("banner", "str", False, "Captured text response, truncated by the scanner."),
            FieldSchema("error", "str", False, "Connection or read error when no banner was captured."),
            FieldSchema("elapsed_ms", "int", False, "Elapsed probe time in milliseconds."),
            FieldSchema("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "network.route.hop": EventSchema(
        topic="network.route.hop",
        summary="One hop observed while tracing a route to a target.",
        fields=(
            FieldSchema("target", "str", True, "Original trace target."),
            FieldSchema("hop", "int", True, "One-based hop number."),
            FieldSchema("host", "str", False, "Hop hostname or address text, when known."),
            FieldSchema("ip", "str", False, "Concrete hop IP address, when known."),
            FieldSchema("rtt_ms", "number", False, "First observed round-trip time in milliseconds."),
            FieldSchema("status", "str", False, "Hop observation status.", ("responded", "timeout")),
            FieldSchema("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "smb.share.found": EventSchema(
        topic="smb.share.found",
        summary="An SMB share was observed on a host.",
        fields=(
            FieldSchema("host", "str", True, "SMB server host."),
            FieldSchema("share", "str", True, "Share name."),
            FieldSchema("ip", "str", False, "Concrete server IP address."),
            FieldSchema("port", "int", False, "SMB service port, usually 445."),
            FieldSchema("protocol", "str", False, "Protocol label, usually smb.", ("smb",)),
            FieldSchema("access", "str", False, "Observed access.", ("unknown", "none", "read", "write", "read_write")),
            FieldSchema("authenticated", "bool", False, "Whether authenticated credentials were used."),
            FieldSchema("remark", "str", False, "Share comment or tool-provided remark."),
        ),
    ),
    "finding.candidate": EventSchema(
        topic="finding.candidate",
        summary="A normalized finding-shaped observation that deserves review or correlation.",
        fields=(
            FieldSchema("title", "str", True, "Human-readable finding title."),
            FieldSchema("class", "str", True, "Stable Bywaf finding class."),
            FieldSchema("severity", "str", False, "Severity label."),
            FieldSchema("target", "dict", False, "Structured primary target."),
            FieldSchema("target_scope", "dict", False, "Finding grouping scope."),
            FieldSchema("affected", "list", False, "Affected resources."),
            FieldSchema("evidence", "str", False, "Short evidence summary."),
            FieldSchema("recommendation", "str", False, "Operator-facing remediation guidance."),
        ),
        notes=("Use bywaf.finding.candidate_payload(...) when possible.",),
    ),
    "artifact.attached": EventSchema(
        topic="artifact.attached",
        summary="An artifact body was attached to runtime provenance.",
        fields=(
            FieldSchema("artifact_id", "str", True, "Stable artifact serial."),
            FieldSchema("name", "str", True, "Artifact display name."),
            FieldSchema("content_type", "str", True, "MIME type or content label."),
            FieldSchema("sha256", "str", True, "SHA-256 digest of artifact body."),
            FieldSchema("size", "int", True, "Artifact body size in bytes."),
            FieldSchema("commandlet", "str", False, "Producing commandlet."),
            FieldSchema("job_id", "any", False, "Associated job id if available."),
            FieldSchema("pipeline_id", "str", False, "Associated pipeline serial if available."),
            FieldSchema("command_run_id", "str", False, "Associated step serial if available."),
            FieldSchema("note", "str", False, "Operator note or artifact note."),
        ),
    ),
}


def event_schema(topic: str) -> EventSchema | None:
    """Return the shared schema for a topic, if Bywaf defines one."""
    return EVENT_SCHEMAS.get(topic)


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
