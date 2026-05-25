"""Finding grouping helpers.

Provides stable report grouping keys from normalized finding payloads while
leaving semantic target-scope choices to plugins.

Used by:
- finding payload helpers: derive default group keys for candidates.
- report commandlets and tests: collapse related findings for display."""

from __future__ import annotations

from collections.abc import Mapping
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
    if kind == "host":
        return first_string(target, "ip", "host", "hostname")
    if kind == "host_port":
        host = first_string(target, "ip", "host", "hostname")
        port = first_string(target, "port")
        protocol = first_string(target, "protocol", default="tcp")
        return f"{host}:{port}/{protocol}" if host and port else ""
    if kind == "service":
        host = first_string(target, "ip", "host", "hostname")
        port = first_string(target, "port")
        protocol = first_string(target, "protocol", default="tcp")
        scheme = first_string(target, "scheme")
        base = f"{host}:{port}/{protocol}" if host and port else ""
        return f"{base}:{scheme}" if base and scheme else base
    if kind in {"web_origin", "web_app", "web_route"}:
        # Web targets need more than an IP address. `web_origin` groups every
        # path on the same scheme/host/port, while `web_route` keeps individual
        # URLs separate for findings whose impact is route-specific.
        scheme = first_string(target, "scheme", default="https")
        host = first_string(target, "host", "hostname")
        port = first_string(target, "port")
        path = first_string(target, "path")
        origin = f"{scheme}://{host}" if host else ""
        if port and port not in {"80", "443"}:
            origin = f"{origin}:{port}"
        if kind == "web_origin":
            return origin
        if kind == "web_app":
            app = first_string(target, "app", "base_path", default=path)
            return f"{origin}{normalize_path(app)}" if origin else ""
        return f"{origin}{normalize_path(path)}" if origin else ""
    if kind == "cloud_account":
        provider = first_string(target, "provider")
        account = first_string(target, "account", "account_id", "project")
        return f"{provider}:{account}" if provider and account else ""
    if kind == "cloud_resource":
        provider = first_string(target, "provider")
        resource = first_string(target, "arn", "resource", "id", "name")
        return f"{provider}:{resource}" if provider and resource else resource
    if kind == "artifact":
        artifact_id = first_string(target, "artifact", "artifact_id", "id")
        return f"artifact:{artifact_id}" if artifact_id else ""
    return first_string(target, "value", "id", "url", "host")


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
