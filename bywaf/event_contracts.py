"""Shared event payload contracts.

Provides lightweight topic contracts for framework-known event topics. These
contracts make event topics usable as stable interoperability interfaces while
keeping plugin-private topics free-form.

Used by:
- plugin authors and tests: validate payloads for shared topics.
- documentation and future views: describe which fields are safe to depend on.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Literal, Self, TypeVar

FieldType = Literal["any", "bool", "dict", "int", "list", "number", "str"]
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class FieldContract:
    """One field in a shared event payload contract."""

    name: str
    field_type: FieldType = "any"
    required: bool = False
    description: str = ""
    allowed: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventContract:
    """Payload contract for one shared event topic."""

    topic: str
    summary: str
    fields: tuple[FieldContract, ...]
    notes: tuple[str, ...] = ()

    @property
    def required_fields(self) -> tuple[str, ...]:
        """Return required payload field names."""
        return tuple(field.name for field in self.fields if field.required)


class ContractObject:
    """Base class for plugin-owned objects backed by a shared event contract."""

    __topic__: ClassVar[str]

    @classmethod
    def from_event(cls, event: Any) -> Self:
        """Deserialize a shared-contract event into this object type."""
        return contract_object(event, cls.contract_topic(), cls)

    @classmethod
    def contract_topic(cls) -> str:
        """Return the shared event topic this object represents."""
        topic = getattr(cls, "__topic__", "")
        if not topic:
            raise ValueError(f"{cls.__name__} must define __topic__")
        return topic

    def to_payload(self) -> dict[str, Any]:
        """Serialize this object to its shared event contract payload."""
        topic = self.contract_topic()
        contract = event_contract(topic)
        if contract is None:
            raise ValueError(f"unknown shared event contract: {topic}")
        payload = {
            field.name: getattr(self, field.name)
            for field in contract.fields
            if hasattr(self, field.name) and getattr(self, field.name) is not None
        }
        errors = validate_event_payload(topic, payload)
        if errors:
            raise ValueError("; ".join(errors))
        return payload


EVENT_CONTRACTS: dict[str, EventContract] = {
    "host.found": EventContract(
        topic="host.found",
        summary="A host was observed alive or otherwise reachable.",
        fields=(
            FieldContract("host", "str", True, "IP address or hostname used for follow-up work."),
            FieldContract("ip", "str", False, "Concrete IP address when host is a DNS name or alias."),
            FieldContract("name", "str", False, "Original DNS name or operator-provided name."),
            FieldContract("status", "str", False, "Host state.", ("up", "reachable", "unknown")),
            FieldContract("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "name.resolved": EventContract(
        topic="name.resolved",
        summary="A name resolved to one or more concrete addresses.",
        fields=(
            FieldContract("name", "str", True, "Original hostname."),
            FieldContract("host", "str", True, "Resolved address."),
            FieldContract("resolver", "str", False, "Resolver or backend that produced the mapping."),
        ),
    ),
    "port.open": EventContract(
        topic="port.open",
        summary="A network port was observed open on a host.",
        fields=(
            FieldContract("host", "str", True, "Host or address where the port is open."),
            FieldContract("port", "int", True, "Numeric port."),
            FieldContract("protocol", "str", True, "Transport protocol.", ("tcp", "udp")),
            FieldContract("state", "str", False, "Observed port state.", ("open", "open|filtered")),
            FieldContract("service", "str", False, "Best-known service name or probe label."),
            FieldContract("reason", "str", False, "Scanner reason, such as syn-ack."),
            FieldContract("scanner", "str", False, "Tool or backend that produced the observation."),
        ),
    ),
    "http.endpoint": EventContract(
        topic="http.endpoint",
        summary="A reachable HTTP or HTTPS endpoint.",
        fields=(
            FieldContract("url", "str", True, "Canonical endpoint URL."),
            FieldContract("host", "str", True, "Endpoint host."),
            FieldContract("port", "int", True, "Endpoint port."),
            FieldContract("scheme", "str", True, "HTTP scheme.", ("http", "https")),
            FieldContract("status", "int", False, "HTTP status code."),
            FieldContract("method", "str", False, "HTTP method used to probe the endpoint."),
            FieldContract("server", "str", False, "Server header or equivalent banner."),
            FieldContract("error", "str", False, "Probe error if endpoint metadata is partial."),
        ),
    ),
    "smb.share.found": EventContract(
        topic="smb.share.found",
        summary="An SMB share was observed on a host.",
        fields=(
            FieldContract("host", "str", True, "SMB server host."),
            FieldContract("share", "str", True, "Share name."),
            FieldContract("ip", "str", False, "Concrete server IP address."),
            FieldContract("port", "int", False, "SMB service port, usually 445."),
            FieldContract("protocol", "str", False, "Protocol label, usually smb.", ("smb",)),
            FieldContract("access", "str", False, "Observed access.", ("unknown", "none", "read", "write", "read_write")),
            FieldContract("authenticated", "bool", False, "Whether authenticated credentials were used."),
            FieldContract("remark", "str", False, "Share comment or tool-provided remark."),
        ),
    ),
    "finding.candidate": EventContract(
        topic="finding.candidate",
        summary="A normalized finding-shaped observation that deserves review or correlation.",
        fields=(
            FieldContract("title", "str", True, "Human-readable finding title."),
            FieldContract("class", "str", True, "Stable Bywaf finding class."),
            FieldContract("severity", "str", False, "Severity label."),
            FieldContract("target", "dict", False, "Structured primary target."),
            FieldContract("target_scope", "dict", False, "Finding grouping scope."),
            FieldContract("affected", "list", False, "Affected resources."),
            FieldContract("evidence", "str", False, "Short evidence summary."),
            FieldContract("recommendation", "str", False, "Operator-facing remediation guidance."),
        ),
        notes=("Use bywaf.finding.candidate_payload(...) when possible.",),
    ),
    "artifact.attached": EventContract(
        topic="artifact.attached",
        summary="An artifact body was attached to runtime provenance.",
        fields=(
            FieldContract("artifact_id", "str", True, "Stable artifact serial."),
            FieldContract("name", "str", True, "Artifact display name."),
            FieldContract("content_type", "str", True, "MIME type or content label."),
            FieldContract("sha256", "str", True, "SHA-256 digest of artifact body."),
            FieldContract("size", "int", True, "Artifact body size in bytes."),
            FieldContract("commandlet", "str", False, "Producing commandlet."),
            FieldContract("job_id", "any", False, "Associated job id if available."),
            FieldContract("pipeline_id", "str", False, "Associated pipeline serial if available."),
            FieldContract("command_run_id", "str", False, "Associated step serial if available."),
            FieldContract("note", "str", False, "Operator note or artifact note."),
        ),
    ),
}


def event_contract(topic: str) -> EventContract | None:
    """Return the shared contract for a topic, if Bywaf defines one."""
    return EVENT_CONTRACTS.get(topic)


def validate_event_payload(topic: str, payload: Mapping[str, Any]) -> list[str]:
    """Return validation errors for a shared-topic payload.

    Plugin-private topics intentionally return no errors here. They may define
    their own sidecar schemas later without changing the framework registry.
    """
    contract = event_contract(topic)
    if contract is None:
        return []
    errors: list[str] = []
    for field in contract.fields:
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


def contract_payload(event: Any, topic: str) -> Mapping[str, Any]:
    """Return a validated shared-contract payload from an event.

    Plugin authors can use this directly or through ``contract_object`` before
    constructing their own typed domain objects from shared event facts.
    """
    event_topic = getattr(event, "topic", None)
    if event_topic != topic:
        raise ValueError(f"expected {topic} event, got {event_topic}")
    payload = getattr(event, "payload", None)
    if not isinstance(payload, Mapping):
        raise ValueError(f"{topic} payload must be a mapping")
    errors = validate_event_payload(topic, payload)
    if errors:
        raise ValueError("; ".join(errors))
    return payload


def contract_object(event: Any, topic: str, factory: Callable[..., T]) -> T:
    """Deserialize a shared-contract event into a plugin-owned object.

    The factory must accept the contract fields as keyword arguments, which
    makes dataclasses and small typed constructors work naturally.
    """
    contract = event_contract(topic)
    if contract is None:
        raise ValueError(f"unknown shared event contract: {topic}")
    payload = contract_payload(event, topic)
    fields = {field.name: payload[field.name] for field in contract.fields if field.name in payload}
    accepted = accepted_factory_fields(factory)
    if accepted is not None:
        fields = {name: value for name, value in fields.items() if name in accepted}
    return factory(**fields)


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


def field_value_matches(value: Any, field_type: FieldType) -> bool:
    """Return whether a value matches a contract field type."""
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
