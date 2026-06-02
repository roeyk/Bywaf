"""Finding normalization helpers for finding deduplication."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from bywaf.event import Event
from bywaf.plugins.analysis.finding_dedupe_model import (
    NormalizedFinding,
    TargetIdentity,
    best_identifier,
    normalize_text,
)

STATUS_RANKS = {
    "false_positive": 0,
    "speculative": 1,
    "potential": 2,
    "confirmed": 3,
}
UPPERCASE_IDENTIFIER_KEYS = {"cve", "cwe", "ghsa", "osv"}
EMBEDDED_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "cwe": re.compile(r"CWE-\d+", re.IGNORECASE),
    "ghsa": re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE),
    "osv": re.compile(r"OSV-\d+", re.IGNORECASE),
}

def normalize_event(event: Event) -> NormalizedFinding:
    """Convert one source event into a tool-neutral finding candidate."""
    payload = dict(event.payload)
    title = first_text(payload, "title", "message", "description", "name") or event.topic
    target = normalize_target(payload)
    identifiers = normalize_identifiers(payload)
    finding_class = str(payload.get("class") or payload.get("kind") or infer_finding_class(title, payload))
    return NormalizedFinding(
        source_event_id=event.id,
        source_topic=event.topic,
        source_tool=str(payload.get("tool") or payload.get("scanner") or event.source),
        source_step=event.command_run_id,
        title=title,
        finding_class=finding_class,
        status=normalize_status(str(payload.get("status") or payload.get("verification") or status_from_topic(event.topic))),
        confidence=str(payload.get("confidence") or "medium"),
        severity=str(payload.get("severity") or "unknown"),
        target=target,
        identifiers=identifiers,
        evidence=first_text(payload, "evidence", "proof", "details", "data") or "",
        raw=payload,
    )

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


def infer_finding_class(title: str, payload: dict[str, Any]) -> str:
    """Infer a stable finding class from common vulnerability wording."""
    text = normalize_text(" ".join([title, json.dumps(payload, default=str)]))
    rules = (
        ("missing_security_header", ("missing", "header")),
        ("directory_listing", ("directory listing",)),
        ("directory_listing", ("index of",)),
        ("default_credentials", ("default credential", "default password")),
        ("known_vulnerable_component", ("cve-", "vulnerable", "outdated")),
        ("exposed_admin_interface", ("admin", "administrator", "login")),
        ("tls_weak_cipher", ("weak cipher", "tls", "ssl")),
        ("sql_injection_possible", ("sql injection", "sqli")),
    )
    for name, needles in rules:
        if all(needle in text for needle in needles):
            return name
    return "generic_finding"


def stable_finding_id(key: str) -> str:
    """Return a stable normalized finding id."""
    return f"finding-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"


def matched_on(finding: NormalizedFinding) -> list[str]:
    """Describe the match evidence for duplicate decisions."""
    fields = ["target"]
    fields.append("identifier" if best_identifier(finding.identifiers) else "fingerprint")
    if finding.finding_class:
        fields.append("class")
    return fields


def count_decisions(decisions: list[dict[str, Any]]) -> dict[str, int]:
    """Count decisions by type."""
    counts = {key: 0 for key in ("new", "duplicate", "updated", "merge_candidate")}
    for decision in decisions:
        counts[str(decision["decision"])] += 1
    return counts

def first_text(payload: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty string-like payload value."""
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return ""


def status_from_topic(topic: str) -> str:
    """Infer verification status from the source topic."""
    if topic.endswith(".confirmed") or topic == "vulnerability.found":
        return "confirmed"
    if topic.endswith(".false_positive"):
        return "false_positive"
    if topic.endswith(".speculative"):
        return "speculative"
    return "potential"


def normalize_status(value: str) -> str:
    """Normalize status words to Bywaf finding lifecycle values."""
    cleaned = value.strip().lower().replace("-", "_")
    aliases = {"found": "confirmed", "possible": "potential", "unverified": "potential"}
    return aliases.get(cleaned, cleaned if cleaned in STATUS_RANKS else "potential")


def status_rank(status: str) -> int:
    """Return comparable status strength."""
    return STATUS_RANKS.get(normalize_status(status), STATUS_RANKS["potential"])


def normalize_path(value: str) -> str:
    """Normalize URL paths without dropping root."""
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"


def default_port(scheme: str) -> str:
    """Return the default port for common URL schemes."""
    return {"http": "80", "https": "443"}.get(scheme.lower(), "")
