"""Finding normalization helpers for finding deduplication."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from bywaf.event import Event
from bywaf.finding.grouping import finding_group_key
from bywaf.plugins.analysis.finding_dedupe_identifiers import normalize_identifiers
from bywaf.plugins.analysis.finding_dedupe_model import (
    NormalizedFinding,
    best_identifier,
    normalize_text,
)
from bywaf.plugins.analysis.finding_dedupe_targets import normalize_target, normalize_target_scope

STATUS_RANKS = {
    "false_positive": 0,
    "speculative": 1,
    "potential": 2,
    "confirmed": 3,
}

def normalize_event(event: Event) -> NormalizedFinding:
    """Convert one source event into a tool-neutral finding candidate."""
    payload = dict(event.payload)
    title = first_text(payload, "title", "message", "description", "name") or event.topic
    target = normalize_target(payload)
    identifiers = normalize_identifiers(payload)
    finding_class = str(payload.get("class") or payload.get("kind") or infer_finding_class(title, payload))
    source = source_payload(event, payload)
    target_scope = normalize_target_scope(payload)
    return NormalizedFinding(
        source_event_id=event.id,
        source_topic=event.topic,
        source_tool=str(payload.get("tool") or payload.get("scanner") or event.source),
        source_step=event.command_run_id,
        title=title,
        finding_class=finding_class,
        status=normalize_status(str(payload.get("status") or payload.get("verification") or status_from_topic(event.topic))),
        confidence=str(payload.get("confidence") or "medium"),
        confidence_basis=str(payload.get("confidence_basis") or ""),
        severity=str(payload.get("severity") or "unknown"),
        target=target,
        target_scope=target_scope,
        identifiers=identifiers,
        affected=normalize_affected(payload),
        evidence=first_text(payload, "evidence", "proof", "details", "data") or "",
        recommendation=first_text(payload, "recommendation", "remediation") or "",
        group_key=str(payload.get("group_key") or finding_group_key({"class": finding_class, "target_scope": target_scope, "identifiers": identifiers}, fallback="")),
        subjects=dict(payload.get("subjects") or {}) if isinstance(payload.get("subjects"), dict) else {},
        sources=normalize_sources(payload, source),
        raw=payload,
    )

def normalize_affected(payload: dict[str, Any]) -> list[Any]:
    """Return normalized affected entries from finding payloads."""
    affected = payload.get("affected")
    if isinstance(affected, list):
        return [item for item in affected if item not in ("", None, {}, [])]
    return []


def normalize_sources(payload: dict[str, Any], fallback: dict[str, Any]) -> list[dict[str, Any]]:
    """Return source entries from payload plus event provenance fallback."""
    values: list[dict[str, Any]] = []
    raw_sources = payload.get("sources")
    if isinstance(raw_sources, list):
        values.extend(item for item in raw_sources if isinstance(item, dict))
    values.append(fallback)
    return unique_sources(values)


def source_payload(event: Event, payload: dict[str, Any]) -> dict[str, Any]:
    """Return compact source metadata for one normalized event."""
    return compact_source(
        {
            "tool": payload.get("tool") or payload.get("scanner") or event.source,
            "topic": event.topic,
            "event_id": event.id,
            "step": event.command_run_id,
        }
    )


def unique_sources(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return source dictionaries without duplicates."""
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        source = compact_source(value)
        key = json.dumps(source, sort_keys=True, default=str, separators=(",", ":"))
        if source and key not in seen:
            seen.add(key)
            unique.append(source)
    return unique


def compact_source(value: dict[str, Any]) -> dict[str, Any]:
    """Drop empty source metadata fields."""
    return {str(key): item for key, item in value.items() if item not in ("", None, {}, [])}


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
