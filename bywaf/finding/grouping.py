"""Finding grouping helpers.

Provides stable report grouping keys from normalized finding payloads while
leaving semantic target-scope choices to plugins.

Used by:
- finding payload helpers: derive default group keys for candidates.
- report commandlets and tests: collapse related findings for display."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .taxonomy import validate_finding_class


IDENTIFIER_PRIORITY = ("cve", "ghsa", "vendor", "cwe", "owasp", "capec")


def finding_group_key(payload: Mapping[str, Any], *, fallback: str = "") -> str:
    """Return the stable group key for one normalized finding payload.

    Grouping is intentionally mechanical here. Plugins decide the semantic
    scope by setting `group_key`, `target_scope`, or `finding_scope`; the
    framework only turns that declared scope into a deterministic report key.
    """
    explicit = string_value(payload.get("group_key"))
    if explicit:
        return explicit
    target_scope = normalized_target_scope(payload)
    finding_class = string_value(payload.get("class") or payload.get("finding_class"))
    if target_scope and finding_class:
        try:
            validate_finding_class(finding_class)
        except ValueError:
            finding_class = ""
    if target_scope and finding_class:
        identifier = primary_identifier(payload.get("identifiers"))
        parts = [finding_class, f"{target_scope['kind']}:{target_scope['value']}"]
        parts.append(f"{identifier[0]}:{identifier[1]}" if identifier else "class")
        return "|".join(parts)
    finding_id = string_value(payload.get("finding_id"))
    if finding_id:
        return finding_id
    return fallback


def normalized_target_scope(payload: Mapping[str, Any]) -> dict[str, str] | None:
    """Return normalized target scope from explicit payload fields."""
    # Prefer an explicit `target_scope` object because it lets a plugin say
    # exactly whether a finding belongs to a host, service, origin, route, or
    # other domain object. This is what handles cases such as one CVE affecting
    # multiple pages on the same web origin.
    scope = payload.get("target_scope")
    if isinstance(scope, Mapping):
        kind = string_value(scope.get("kind"))
        value = string_value(scope.get("value"))
        if kind and value:
            return {"kind": kind, "value": value}
    # `finding_scope` is the convenience form used by candidate_payload(...).
    # It derives the actual scope value from conventional target fields.
    finding_scope = string_value(payload.get("finding_scope"))
    target = payload.get("target")
    if finding_scope and isinstance(target, Mapping):
        value = target_scope_value(finding_scope, target)
        if value:
            return {"kind": finding_scope, "value": value}
    return None


def target_scope(kind: str, value: str) -> dict[str, str]:
    """Return a normalized target_scope object for candidate_payload(...)."""
    if not kind or not value:
        raise ValueError("target_scope kind and value are required")
    return {"kind": kind, "value": value}


def target_scope_value(kind: str, target: Mapping[str, Any]) -> str:
    """Return a stable target-scope value from conventional target fields."""
    handler = TARGET_SCOPE_VALUE_HANDLERS.get(kind)
    if handler is not None:
        return handler(target)
    return first_string(target, "value", "id", "url", "host")


def host_scope_value(target: Mapping[str, Any]) -> str:
    """Return host-level target identity."""
    return first_string(target, "ip", "host", "hostname")


def host_port_scope_value(target: Mapping[str, Any]) -> str:
    """Return host/port/protocol target identity."""
    host = first_string(target, "ip", "host", "hostname")
    port = first_string(target, "port")
    protocol = first_string(target, "protocol", default="tcp")
    return f"{host}:{port}/{protocol}" if host and port else ""


def service_scope_value(target: Mapping[str, Any]) -> str:
    """Return service target identity, including scheme when present."""
    scheme = first_string(target, "scheme")
    base = host_port_scope_value(target)
    return f"{base}:{scheme}" if base and scheme else base


def web_origin_scope_value(target: Mapping[str, Any]) -> str:
    """Return scheme/host/port identity for web-origin findings."""
    scheme = first_string(target, "scheme", default="https")
    host = first_string(target, "host", "hostname")
    port = first_string(target, "port")
    origin = f"{scheme}://{host}" if host else ""
    if port and port not in {"80", "443"}:
        origin = f"{origin}:{port}"
    return origin


def web_app_scope_value(target: Mapping[str, Any]) -> str:
    """Return web application identity below an origin."""
    origin = web_origin_scope_value(target)
    path = first_string(target, "path")
    app = first_string(target, "app", "base_path", default=path)
    return f"{origin}{normalize_path(app)}" if origin else ""


def web_route_scope_value(target: Mapping[str, Any]) -> str:
    """Return route-specific web target identity."""
    origin = web_origin_scope_value(target)
    path = first_string(target, "path")
    return f"{origin}{normalize_path(path)}" if origin else ""


def cloud_account_scope_value(target: Mapping[str, Any]) -> str:
    """Return cloud account or project identity."""
    provider = first_string(target, "provider")
    account = first_string(target, "account", "account_id", "project")
    return f"{provider}:{account}" if provider and account else ""


def cloud_resource_scope_value(target: Mapping[str, Any]) -> str:
    """Return cloud resource identity."""
    provider = first_string(target, "provider")
    resource = first_string(target, "arn", "resource", "id", "name")
    return f"{provider}:{resource}" if provider and resource else resource


def artifact_scope_value(target: Mapping[str, Any]) -> str:
    """Return artifact identity."""
    artifact_id = first_string(target, "artifact", "artifact_id", "id")
    return f"artifact:{artifact_id}" if artifact_id else ""


TARGET_SCOPE_VALUE_HANDLERS: dict[str, Callable[[Mapping[str, Any]], str]] = {
    "artifact": artifact_scope_value,
    "cloud_account": cloud_account_scope_value,
    "cloud_resource": cloud_resource_scope_value,
    "host": host_scope_value,
    "host_port": host_port_scope_value,
    "service": service_scope_value,
    "web_app": web_app_scope_value,
    "web_origin": web_origin_scope_value,
    "web_route": web_route_scope_value,
}


def primary_identifier(value: Any) -> tuple[str, str] | None:
    """Return the highest-priority external identifier from a finding payload."""
    if not isinstance(value, Mapping):
        return None
    for key in IDENTIFIER_PRIORITY:
        raw = value.get(key)
        if isinstance(raw, str) and raw:
            return key, raw.upper() if key == "cve" else raw
        if isinstance(raw, list):
            items = sorted(str(item) for item in raw if item)
            if items:
                first = items[0]
                return key, first.upper() if key == "cve" else first
    return None


def first_string(target: Mapping[str, Any], *keys: str, default: str = "") -> str:
    """Return the first non-empty target field as a string."""
    for key in keys:
        value = string_value(target.get(key))
        if value:
            return value
    return default


def string_value(value: Any) -> str:
    """Return a stripped string for primitive values."""
    if value is None:
        return ""
    return str(value).strip()


def normalize_path(value: str) -> str:
    """Return a stable web path component."""
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"
