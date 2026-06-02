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
    severity: str
    target: TargetIdentity
    identifiers: dict[str, list[str]]
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def exact_key(self) -> str:
        """Return the strongest available dedupe key for this finding."""
        identifier = best_identifier(self.identifiers)
        if identifier:
            return "|".join(("id", self.target.key(), identifier))
        return "|".join(("fingerprint", self.target.key(), self.finding_class, evidence_fingerprint(self)))

    def fuzzy_basis(self) -> str:
        """Return normalized text used for last-resort fuzzy candidate checks."""
        return normalize_text(" ".join([self.title, self.evidence]))

    def as_payload(self, finding_id: str) -> dict[str, Any]:
        """Return the canonical event payload for this finding."""
        return {
            "finding_id": finding_id,
            "status": self.status,
            "confidence": self.confidence,
            "severity": self.severity,
            "class": self.finding_class,
            "title": self.title,
            "target": self.target.as_payload(),
            "identifiers": self.identifiers,
            "evidence": self.evidence,
            "sources": [
                {
                    "tool": self.source_tool,
                    "topic": self.source_topic,
                    "event_id": self.source_event_id,
                    "step": self.source_step,
                }
            ],
        }


@dataclass(slots=True)
class CanonicalFinding:
    """One deduped finding and the source events attached to it."""

    finding_id: str
    finding: NormalizedFinding
    source_event_ids: list[int | None] = field(default_factory=list)

    def add_source(self, finding: NormalizedFinding) -> None:
        """Remember the source event that contributed to this finding."""
        self.source_event_ids.append(finding.source_event_id)


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
