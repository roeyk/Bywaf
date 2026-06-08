"""Model types for finding deduplication."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """Canonical identity of the affected target."""

    scheme: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    parameter: str = ""
    service: str = ""
    product: str = ""
    version: str = ""

    def as_payload(self) -> dict[str, str]:
        """Return non-empty target fields for event payloads."""
        values = {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "parameter": self.parameter,
            "service": self.service,
            "product": self.product,
            "version": self.version,
        }
        return {key: value for key, value in values.items() if value}

    def key(self) -> str:
        """Return a deterministic key used for dedupe comparisons."""
        return "|".join(
            (
                self.scheme,
                self.host,
                self.port,
                self.path,
                self.parameter,
                self.service,
                self.product,
                self.version,
            )
        )


@dataclass(slots=True)
class NormalizedFinding:
    """Tool-neutral finding representation used by the deduper."""

    source_event_id: int | None
    source_topic: str
    source_tool: str
    source_step: str | None
    title: str
    finding_class: str
    status: str
    confidence: str
    confidence_basis: str
    severity: str
    target: TargetIdentity
    target_scope: dict[str, str]
    identifiers: dict[str, list[str]]
    affected: list[Any] = field(default_factory=list)
    evidence: str = ""
    recommendation: str = ""
    group_key: str = ""
    subjects: dict[str, Any] = field(default_factory=dict)
    sources: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def exact_key(self) -> str:
        """Return the strongest available dedupe key for this finding."""
        identifier = best_identifier(self.identifiers)
        if identifier:
            return "|".join(("id", self.target_identity_key(), self.finding_class, identifier))
        return "|".join(("fingerprint", self.target_identity_key(), self.finding_class, evidence_fingerprint(self)))

    def target_identity_key(self) -> str:
        """Return the target identity used for dedupe matching."""
        if self.target_scope:
            return f"{self.target_scope.get('kind', '')}:{self.target_scope.get('value', '')}"
        return self.target.key()

    def fuzzy_basis(self) -> str:
        """Return normalized text used for last-resort fuzzy candidate checks."""
        return normalize_text(" ".join([self.title, self.evidence]))

    def as_payload(self, finding_id: str) -> dict[str, Any]:
        """Return the canonical event payload for this finding."""
        return {
            "finding_id": finding_id,
            "status": self.status,
            "confidence": self.confidence,
            "confidence_basis": self.confidence_basis,
            "severity": self.severity,
            "class": self.finding_class,
            "title": self.title,
            "target_scope": self.target_scope,
            "target": self.target.as_payload(),
            "identifiers": self.identifiers,
            "affected": self.affected,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "group_key": self.group_key,
            "subjects": self.subjects,
            "sources": self.sources,
        }

    def merge_from(self, finding: NormalizedFinding) -> None:
        """Merge non-conflicting finding-model fields from another source."""
        self.identifiers = merge_identifier_values(self.identifiers, finding.identifiers)
        self.affected = unique_json_values([*self.affected, *finding.affected])
        self.sources = unique_json_values([*self.sources, *finding.sources])
        self.subjects = {**finding.subjects, **self.subjects}
        if not self.target_scope and finding.target_scope:
            self.target_scope = finding.target_scope
        if not self.group_key and finding.group_key:
            self.group_key = finding.group_key
        if not self.recommendation and finding.recommendation:
            self.recommendation = finding.recommendation
        if not self.confidence_basis and finding.confidence_basis:
            self.confidence_basis = finding.confidence_basis


@dataclass(slots=True)
class CanonicalFinding:
    """One deduped finding and the source events attached to it."""

    finding_id: str
    finding: NormalizedFinding
    source_event_ids: list[int | None] = field(default_factory=list)

    def add_source(self, finding: NormalizedFinding) -> None:
        """Remember the source event that contributed to this finding."""
        self.source_event_ids.append(finding.source_event_id)
        self.finding.merge_from(finding)


def merge_identifier_values(
    first: dict[str, list[str]],
    second: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Return identifier values merged by identifier family."""
    merged = {key: list(values) for key, values in first.items()}
    for key, values in second.items():
        merged.setdefault(key, [])
        merged[key].extend(values)
    return {key: sorted(set(values)) for key, values in merged.items() if values}


def unique_json_values(values: list[Any]) -> list[Any]:
    """Return values with stable JSON-equivalent duplicates removed."""
    unique: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return unique


def best_identifier(identifiers: dict[str, list[str]]) -> str:
    """Return the strongest standardized identifier for exact matching."""
    for key in ("cve", "ghsa", "osv", "cwe", "vendor", "owasp"):
        values = identifiers.get(key, [])
        if values:
            return f"{key}:{values[0]}"
    return ""


def evidence_fingerprint(finding: NormalizedFinding) -> str:
    """Return a hash of stable finding fields when identifiers are absent."""
    basis = "|".join(
        [
            finding.title.lower(),
            finding.evidence.lower(),
            json.dumps(finding.identifiers, sort_keys=True),
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def normalize_text(value: str) -> str:
    """Normalize free text for comparison."""
    return re.sub(r"\s+", " ", value.lower()).strip()
