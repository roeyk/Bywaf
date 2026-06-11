"""Finding report row normalization helpers.

Used by:
- `finding_report.FindingReport` to render the standalone finding report table.
- `analysis.report.tables` to reuse the same normalized row shape for grouped
  report views.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bywaf.event import Event
from bywaf.plugins.analysis.finding.dedupe import normalize_event
from bywaf.plugins.analysis.finding_display import affected_values, compact_table_text
from bywaf.plugins.analysis.finding.topics import REPORT_FINDING_TOPICS


def finding_rows(events: list[Event], *, include_candidates: bool) -> list[dict[str, str]]:
    """Convert finding events into the requested report columns."""
    rows: list[dict[str, str]] = []
    seen_finding_ids: set[str] = set()
    for event in events:
        if event.topic == "finding.merge_candidate" and not include_candidates:
            continue
        row = row_from_event(event)
        finding_id = str(event.payload.get("finding_id") or "")
        if finding_id and event.topic in {"finding.candidate", "finding.confirmed", "finding.new"}:
            # Keep the table readable when a commandlet emitted the same
            # normalized finding more than once in the selected scope.
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)
        rows.append(row)
    return rows


def row_from_event(event: Event) -> dict[str, str]:
    """Return one reporting row from a normalized or raw finding event."""
    if event.topic in REPORT_FINDING_TOPICS:
        payload = event.payload
        if event.topic == "finding.merge_candidate":
            payload = candidate_payload(payload)
        return row_from_payload(payload)
    normalized = normalize_event(event)
    return {
        "finding_name": normalized.title,
        "description": compact_table_text(normalized.evidence or normalized.finding_class),
        "hosts_affected": host_from_target(normalized.target.as_payload()),
        "cve": cve_values(normalized.identifiers),
        "severity": normalized.severity,
        "recommendation": compact_table_text(recommendation_for(normalized.finding_class, normalized.raw)),
    }


def row_from_payload(payload: Mapping[str, Any]) -> dict[str, str]:
    """Return one reporting row from a normalized finding payload."""
    title = str(payload.get("title") or payload.get("class") or "finding")
    finding_class = str(payload.get("class") or "")
    description = compact_table_text(payload.get("description") or payload.get("evidence") or finding_class)
    identifiers = identifiers_from_payload(payload)
    return {
        "finding_name": title,
        "description": description,
        "hosts_affected": "; ".join(affected_values([payload])) or host_from_target(payload.get("target")),
        "cve": cve_values(identifiers),
        "severity": str(payload.get("severity") or "unknown"),
        "recommendation": compact_table_text(recommendation_for(finding_class, dict(payload))),
    }


def candidate_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the nested candidate payload for merge-candidate rows."""
    candidate = payload.get("candidate")
    if isinstance(candidate, Mapping):
        return candidate
    return payload


def identifiers_from_payload(payload: Mapping[str, Any]) -> dict[str, list[str]]:
    """Return normalized identifiers from a finding payload."""
    raw = payload.get("identifiers")
    if not isinstance(raw, Mapping):
        return {}
    identifiers: dict[str, list[str]] = {}
    for key, value in raw.items():
        values = value if isinstance(value, list) else [value]
        identifiers[str(key).lower()] = [str(item) for item in values if str(item)]
    return identifiers


def cve_values(identifiers: Mapping[str, list[str]]) -> str:
    """Return comma-separated CVE identifiers."""
    return ", ".join(identifiers.get("cve", ()))


def host_from_target(target: object) -> str:
    """Return a compact affected-host string from a target payload."""
    if not isinstance(target, Mapping):
        return ""
    host = str(target.get("host") or "")
    scheme = str(target.get("scheme") or "")
    port = str(target.get("port") or "")
    path = str(target.get("path") or "")
    if host:
        authority = host if not port else f"{host}:{port}"
        return f"{scheme}://{authority}{path}" if scheme else f"{authority}{path}"
    url = target.get("url")
    return str(url) if url else ""


def recommendation_for(finding_class: str, payload: Mapping[str, Any]) -> str:
    """Return a supplied remediation or a conservative class-based suggestion."""
    for key in ("recommendation", "remediation", "solution", "fix"):
        value = payload.get(key)
        if value:
            return str(value)
    recommendations = {
        "missing_security_header": "Add the missing security header and verify it is present on affected responses.",
        "directory_listing": "Disable directory listing or restrict access to the affected path.",
        "default_credentials": "Change default credentials and verify authentication controls.",
        "known_vulnerable_component": "Upgrade or patch the affected component and retest.",
        "exposed_admin_interface": "Restrict administrative interfaces to authorized networks and require strong authentication.",
        "tls_weak_cipher": "Disable weak TLS protocols/ciphers and retest the service.",
        "sql_injection_possible": "Validate input handling and confirm with safe, authorized testing before remediation.",
    }
    return recommendations.get(finding_class, "Review the source evidence, confirm impact, and remediate according to the affected component.")
