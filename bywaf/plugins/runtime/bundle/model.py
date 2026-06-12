"""Core bundle data model and selector helpers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

BUNDLE_ACTIONS = ("add", "create", "export", "list", "seal", "show", "verify")
BUNDLE_CONTENT_KINDS = ("audit", "evidence", "reports")


@dataclass(frozen=True, slots=True)
class Bundle:
    """Reconstructed bundle state from durable audit events.

    Constructed by: `all_bundles()` while replaying bundle events.
    Used by: bundle action handlers, manifest generation, sealing, and export.
    """

    name: str
    bundle_id: str
    created_at: str
    items: tuple[dict[str, Any], ...]
    sealed: dict[str, Any] | None = None


def parse_bundle_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse bundle key=value selectors and flags."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if token in {"--sign", *BUNDLE_CONTENT_KINDS}:
            continue
        if "=" not in token:
            raise ValueError(f"invalid bundle selector: {token}")
        key, value = token.split("=", 1)
        if not value:
            raise ValueError(f"bundle selector {key}= requires a value")
        selectors[key] = value
    return selectors


def require_selector(selectors: dict[str, str], name: str) -> str:
    """Return a required selector."""
    try:
        return selectors[name]
    except KeyError as exc:
        raise ValueError(f"bundle {name}= is required") from exc


def first_content_kind(tokens: list[str]) -> str | None:
    """Return the first content kind token."""
    for token in tokens:
        if token in BUNDLE_CONTENT_KINDS:
            return token
    return None


def split_csv(value: str) -> list[str]:
    """Split a comma-separated selector value."""
    return [item.strip() for item in value.split(",") if item.strip()]


def canonical_json(value: Any) -> bytes:
    """Return deterministic JSON bytes for hashing/signing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
