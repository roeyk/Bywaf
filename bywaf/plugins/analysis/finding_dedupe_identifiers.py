"""Identifier extraction helpers for finding dedupe normalization.

Used by: `finding_dedupe_normalize.normalize_event()` to normalize explicit
identifier payloads and extract embedded CVE/CWE/GHSA/OSV tokens from older
free-form tool events.
"""

from __future__ import annotations

import json
import re
from typing import Any

UPPERCASE_IDENTIFIER_KEYS = {"cve", "cwe", "ghsa", "osv"}
EMBEDDED_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "cwe": re.compile(r"CWE-\d+", re.IGNORECASE),
    "ghsa": re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE),
    "osv": re.compile(r"OSV-\d+", re.IGNORECASE),
}


def normalize_identifiers(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Normalize explicit and embedded vulnerability identifiers."""
    identifiers = explicit_identifiers(payload.get("identifiers"))
    # Some older plugin payloads only mention CVEs/CWEs in text fields. Scan the
    # JSON representation so those findings can still dedupe with normalized
    # payloads that use the `identifiers` object.
    add_embedded_identifiers(identifiers, payload)
    return canonical_identifiers(identifiers)


def explicit_identifiers(raw: Any) -> dict[str, list[str]]:
    """Return normalized identifier lists from an explicit payload field."""
    if not isinstance(raw, dict):
        return {}
    identifiers: dict[str, list[str]] = {}
    for key, value in raw.items():
        values = value if isinstance(value, list) else [value]
        identifiers[str(key).lower()] = sorted({str(item) for item in values if str(item)})
    return identifiers


def add_embedded_identifiers(identifiers: dict[str, list[str]], payload: dict[str, Any]) -> None:
    """Extract identifier-looking tokens from legacy free-form payload text."""
    text = json.dumps(payload, sort_keys=True, default=str)
    for key, pattern in EMBEDDED_IDENTIFIER_PATTERNS.items():
        add_identifiers(identifiers, key, pattern.findall(text))


def canonical_identifiers(identifiers: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return sorted identifier values with canonical casing."""
    return {
        key: sorted({canonical_identifier_value(key, value) for value in values})
        for key, values in identifiers.items()
        if values
    }


def canonical_identifier_value(key: str, value: str) -> str:
    """Return canonical display form for one identifier value."""
    return value.upper() if key in UPPERCASE_IDENTIFIER_KEYS else value


def add_identifiers(identifiers: dict[str, list[str]], key: str, values: list[str]) -> None:
    """Merge identifier values into a normalized identifier dictionary."""
    identifiers.setdefault(key, [])
    identifiers[key].extend(values)
