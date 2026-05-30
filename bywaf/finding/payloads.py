"""Finding candidate helpers.

Provides small constructors for normalized finding-candidate payloads so
plugins do not invent incompatible finding shapes.

Used by:
- bundled commandlets: promote selected fact events into reviewable finding
  candidates.
- analysis commandlets: normalize and report candidate payloads."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .grouping import finding_group_key as derived_finding_group_key
from .grouping import normalized_target_scope
from .subjects import infer_subjects, merge_subjects
from .taxonomy import validate_finding_class


def candidate_payload(
    *,
    title: str,
    finding_class: str,
    target: dict[str, Any],
    severity: str = "info",
    confidence: str = "medium",
    evidence: Any = "",
    recommendation: str = "",
    identifiers: dict[str, list[str]] | None = None,
    source: dict[str, Any] | None = None,
    finding_scope: str = "",
    target_scope: dict[str, Any] | None = None,
    affected: list[dict[str, Any]] | None = None,
    group_key: str = "",
    subjects: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a normalized finding candidate payload."""
    finding_class = validate_finding_class(finding_class)
    # Keep this constructor boring and explicit. Plugin authors should provide
    # semantic fields, while grouping/reporting code derives operational keys.
    payload = {
        "status": "potential",
        "confidence": confidence,
        "severity": severity,
        "class": finding_class,
        "title": title,
        "finding_scope": finding_scope,
        "target_scope": compact(target_scope or {}),
        "target": compact(target),
        "identifiers": identifiers or {},
        "affected": [compact(item) for item in affected or []],
        "group_key": group_key,
        "evidence": evidence,
        "recommendation": recommendation,
        "sources": [compact(source or {})],
    }
    if not payload["target_scope"] and finding_scope:
        # Older/simple plugins may provide finding_scope instead of a full
        # target_scope object; normalize it so reporting can group consistently.
        derived_scope = normalized_target_scope(payload)
        if derived_scope:
            payload["target_scope"] = derived_scope
    if not payload["group_key"]:
        # group_key controls report grouping. finding_id below identifies this
        # exact candidate shape, so the two values intentionally differ.
        payload["group_key"] = derived_finding_group_key(payload, fallback="")
    payload["finding_id"] = stable_finding_id(payload)
    payload["subjects"] = merge_subjects(infer_subjects(payload), subjects)
    return compact(payload)


def telnet_open_candidate(port_payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a finding candidate for an exposed Telnet service."""
    from ..plugins.network.portscanner.findings import telnet_open_candidate as plugin_candidate

    return plugin_candidate(port_payload)


def missing_http_security_header_candidates(headers_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return finding candidates for missing high-value HTTP security headers."""
    from ..plugins.http.http_headers.findings import missing_security_header_candidates
    from ..plugins.http.http_headers.models import HeaderProbeResult, HeaderTarget

    port = int(headers_payload.get("port") or 0)
    result = HeaderProbeResult(
        target=HeaderTarget(
            host=str(headers_payload.get("host") or ""),
            port=port,
            use_ssl=port == 443,
        ),
        status=int(headers_payload.get("status") or 0),
        headers=dict(headers_payload.get("headers") or {}),
    )
    return missing_security_header_candidates(result)


def stable_finding_id(payload: dict[str, Any]) -> str:
    """Return a deterministic id for one candidate payload."""
    # Evidence is deliberately omitted so repeated observations of the same
    # issue remain easy to connect even if proof snippets differ slightly.
    basis = {
        "class": payload.get("class"),
        "identifiers": payload.get("identifiers"),
        "target": payload.get("target"),
        "title": payload.get("title"),
    }
    encoded = json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "finding-" + hashlib.sha256(encoded).hexdigest()[:24]


def compact(payload: dict[str, Any]) -> dict[str, Any]:
    """Return payload with empty values removed recursively."""
    compacted: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = compact(value)
            if nested:
                compacted[key] = nested
        elif isinstance(value, list):
            values = [item for item in value if item not in ("", None, {}, [])]
            if values:
                compacted[key] = values
        elif value not in ("", None):
            compacted[key] = value
    return compacted
