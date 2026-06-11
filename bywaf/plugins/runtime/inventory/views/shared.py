"""Shared helpers for inventory renderers."""

from __future__ import annotations

import ipaddress
from typing import Any


def add_value(values: set[str], value: object) -> None:
    """Add a non-empty string value to a set."""
    if value not in (None, ""):
        values.add(str(value))

def join_values(values: set[str], *, limit: int | None = None) -> str:
    """Join a set of values with a bounded display length."""
    ordered = sorted(values, key=str)
    visible = ordered[:limit] if limit is not None else ordered
    suffix = "" if limit is None or len(ordered) <= limit else f", +{len(ordered) - limit}"
    return ", ".join(visible) + suffix


def split_sort(sort: str, default: str) -> tuple[str, bool]:
    """Return normalized sort key and descending flag."""
    value = sort or default
    return (value[1:], True) if value.startswith("-") else (value, False)


def sort_note(sort: str, default: str) -> str:
    """Return a compact sort annotation for inventory output."""
    key, descending = split_sort(sort, default)
    direction = "descending" if descending else "ascending"
    opposite = key if descending else f"-{key}"
    opposite_direction = "ascending" if descending else "descending"
    return f"sorted by {key} {direction} (use sort={opposite} to sort {opposite_direction})"


def port_label(payload: dict[str, Any]) -> str:
    """Return compact port/protocol/service text."""
    if payload.get("port") in (None, ""):
        return ""
    endpoint = f"{payload.get('port')}/{payload.get('protocol') or 'tcp'}"
    service = str(payload.get("service") or "")
    return f"{endpoint} {service}".strip()

def default_port(payload: dict[str, Any]) -> int:
    """Return the implied port for common web schemes."""
    scheme = str(payload.get("scheme") or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return 0

def format_product(payload: dict[str, Any]) -> str:
    """Return product/version text."""
    product = str(payload.get("product") or "")
    version = str(payload.get("version") or "")
    return f"{product} {version}".strip()

def finding_hosts(payload: dict[str, Any]) -> set[str]:
    """Extract host-like finding targets."""
    values: set[str] = set()
    for candidate in finding_target_values(payload):
        if "://" not in candidate:
            values.add(candidate)
    return values

def finding_urls(payload: dict[str, Any]) -> set[str]:
    """Extract URL-like finding targets."""
    return {candidate for candidate in finding_target_values(payload) if "://" in candidate}

def finding_target_values(payload: dict[str, Any]) -> set[str]:
    """Extract target strings from common finding payload shapes."""
    values: set[str] = set()
    for key in ("target", "target_scope"):
        target = payload.get(key)
        if isinstance(target, dict):
            add_value(values, target.get("value") or target.get("host") or target.get("url"))
    affected = payload.get("affected")
    if isinstance(affected, list):
        for item in affected:
            if isinstance(item, dict):
                add_value(values, item.get("value") or item.get("host") or item.get("url"))
            else:
                add_value(values, item)
    return values

def host_sort_value(value: str) -> tuple[int, bytes | str]:
    """Sort IPs numerically and names lexically."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return (99, value)
    return (address.version, address.packed)
