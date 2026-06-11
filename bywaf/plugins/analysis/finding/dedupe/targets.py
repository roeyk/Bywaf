"""Target normalization helpers for finding dedupe.

Used by: `finding.dedupe.normalize.normalize_event()` to collapse URL, nested
target, and top-level host/port/path payload shapes into one `TargetIdentity`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from bywaf.finding.grouping import normalized_target_scope
from bywaf.plugins.analysis.finding.dedupe.model import TargetIdentity


def normalize_target(payload: dict[str, Any]) -> TargetIdentity:
    """Normalize target identity from common finding payload shapes."""
    # Dedupe accepts legacy/raw tool payloads, so target data may be embedded as
    # a URL, split across fields, or nested under `target`. Normalize it once
    # before comparing findings.
    target_payload = nested_target_payload(payload)
    url = target_field(payload, target_payload, "url")
    parsed = urlparse(url)
    scheme = target_field(payload, target_payload, "scheme", parsed.scheme)
    host = target_field(payload, target_payload, "host", parsed.hostname or "")
    port = target_field(payload, target_payload, "port", str(parsed.port or default_port(scheme)))
    path = target_field(payload, target_payload, "path", parsed.path or "/")
    return TargetIdentity(
        scheme=scheme.lower(),
        host=host.lower(),
        port=port,
        path=normalize_path(path),
        parameter=target_field(payload, target_payload, "parameter"),
        service=target_field(payload, target_payload, "service"),
        product=target_field(payload, target_payload, "product"),
        version=target_field(payload, target_payload, "version"),
    )


def normalize_target_scope(payload: dict[str, Any]) -> dict[str, str]:
    """Return normalized target_scope fields for canonical finding payloads."""
    scope = normalized_target_scope(payload)
    return scope or {}


def nested_target_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return nested target fields when the payload has a target object."""
    target = payload.get("target")
    return target if isinstance(target, dict) else {}


def target_field(
    payload: dict[str, Any],
    target_payload: dict[str, Any],
    key: str,
    default: object = "",
) -> str:
    """Return a target field from nested target, top level, or default."""
    value = target_payload.get(key)
    if value is None or value == "":
        value = payload.get(key)
    if value is None or value == "":
        value = default
    return str(value)


def normalize_path(value: str) -> str:
    """Normalize URL paths without dropping root."""
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"


def default_port(scheme: str) -> str:
    """Return the default port for common URL schemes."""
    return {"http": "80", "https": "443"}.get(scheme.lower(), "")
