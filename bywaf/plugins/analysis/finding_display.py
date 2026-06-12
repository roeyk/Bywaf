"""Shared compact display helpers for finding-oriented reports.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def affected_values(payloads: list[Mapping[str, Any]]) -> list[str]:
    """Return unique affected targets from finding payloads."""
    values: list[str] = []
    for payload in payloads:
        payload_values = values_from_affected(payload.get("affected"))
        values.extend(payload_values)
        if not payload_values and (target_value := compact_target_value(payload.get("target"))):
            values.append(target_value)
    return unique_compact_values(values)


def values_from_affected(raw: object) -> list[str]:
    """Return display strings from a normalized affected list."""
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw:
        value = compact_target_value(item)
        if value:
            values.append(value)
    return values


def compact_target_value(raw: object) -> str:
    """Return one compact target/affected resource string."""
    if not isinstance(raw, Mapping):
        return str(raw) if raw else ""
    url = raw.get("url")
    if url:
        return str(url)
    host = str(raw.get("host") or raw.get("ip") or "")
    port = str(raw.get("port") or "")
    protocol = str(raw.get("protocol") or "")
    path = str(raw.get("path") or "")
    scheme = str(raw.get("scheme") or "")
    if host:
        authority = f"{host}:{port}" if port else host
        if protocol:
            authority = f"{authority}/{protocol}"
        return f"{scheme}://{authority}{path}" if scheme else f"{authority}{path}"
    return compact_table_text(raw)


def compact_table_text(value: object) -> str:
    """Return single-line text for compact report details and tables."""
    return " ".join(str(value).split())


def unique_compact_values(values: Iterable[object]) -> list[str]:
    """Return stable unique non-empty compact strings."""
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = compact_table_text(value)
        if text and text not in seen:
            unique.append(text)
            seen.add(text)
    return unique
