"""Nikto finding normalization and publication helpers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from bywaf.plugin import CommandContext

# Nikto findings are cross-published so older consumers, generic vulnerability
# views, and finding_dedupe/report can all see the same normalized payload.
# publish_finding() is the only writer for this topic fan-out.
FINDING_TOPICS = (
    "nikto.finding",
    "vulnerability.found",
    "vulnerability.potential",
)


def normalize_findings(target: dict[str, Any], data: Any, artifact_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Nikto-specific records into Bywaf vulnerability payloads.

    Called by: `process.run_target()` after Nikto JSON has been loaded. The
    returned payloads are consumed by `publish_finding()`, finding_dedupe, report
    rendering, and evidence bundles.
    """
    findings: list[dict[str, Any]] = []
    for record in extract_finding_records(data):
        message = finding_message(record)
        if not message:
            continue
        identifiers = finding_identifiers(record)
        finding_id = stable_finding_id(target, record, message)
        severity = str(record.get("severity") or record.get("level") or "unknown")
        path = str(record.get("url") or record.get("uri") or record.get("path") or "")
        method = str(record.get("method") or "")
        # This wrapper emits both Nikto-native and compatibility topics. The
        # normalized fields below give finding_dedupe/report enough structure to
        # group results even before a dedicated candidate_payload migration.
        finding = {
            "finding_id": finding_id,
            "scanner": "nikto",
            "tool": "nikto",
            "target": target,
            "url": target["url"],
            "host": target.get("host", ""),
            "port": target.get("port"),
            "scheme": target.get("scheme", ""),
            "title": message,
            "message": message,
            "evidence": finding_evidence(record),
            "path": path,
            "method": method,
            "severity": severity,
            "confidence": str(record.get("confidence") or "medium"),
            "verification": "potential",
            "identifiers": identifiers,
            "raw": record,
            **artifact_payload,
        }
        findings.append(finding)
    return findings


def extract_finding_records(data: Any) -> list[dict[str, Any]]:
    """Extract finding-like dictionaries from common Nikto JSON layouts.

    Called by: `normalize_findings()`. Nikto output differs by version and
    wrapper, so this accepts lists, common top-level collection keys, direct
    finding dictionaries, and nested dictionaries/lists.
    """
    records: list[dict[str, Any]] = []
    if isinstance(data, list):
        for item in data:
            records.extend(extract_finding_records(item))
        return records
    if not isinstance(data, dict):
        return records

    # Nikto JSON is not stable across every version/wrapper. Check common
    # top-level collection keys first, then recurse below for nested variants.
    for key in ("vulnerabilities", "findings", "items"):
        value = data.get(key)
        if isinstance(value, list):
            records.extend(dict(item) for item in value if isinstance(item, dict))

    if is_finding_record(data):
        records.append(dict(data))

    for value in data.values():
        if isinstance(value, (dict, list)):
            # Nikto JSON layouts vary across versions and wrappers. Recursing
            # lets us support nested records without committing to one schema.
            records.extend(extract_finding_records(value))
    return unique_records(records)


def is_finding_record(record: dict[str, Any]) -> bool:
    """Return whether a dictionary looks like a Nikto finding.

    Called by: `extract_finding_records()` as the schema-flexible record gate.
    A candidate must include both descriptive text and an identifier/path hint.
    """
    keys = {key.lower() for key in record}
    return bool(keys & {"msg", "message", "description"}) and bool(keys & {"id", "uri", "url", "osvdb", "cve"})


def unique_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate record objects produced by recursive extraction.

    Called by: `extract_finding_records()` after recursive traversal. Stable
    JSON serialization gives equivalent nested records the same marker.
    """
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for record in records:
        marker = json.dumps(record, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(record)
    return unique


def finding_message(record: dict[str, Any]) -> str:
    """Return the best human-facing message from a Nikto finding record.

    Called by: `normalize_findings()` before deciding whether a record is useful
    enough to become a finding.
    """
    for key in ("msg", "message", "description", "name", "title"):
        value = record.get(key)
        if value:
            return str(value)
    return ""


def finding_evidence(record: dict[str, Any]) -> str:
    """Return compact evidence text from a Nikto finding record.

    Called by: `normalize_findings()` to preserve a short proof string in the
    structured finding while the full raw Nikto output remains artifact-backed.
    """
    for key in ("evidence", "data", "details", "references"):
        value = record.get(key)
        if value:
            return str(value)
    return ""


def finding_identifiers(record: dict[str, Any]) -> dict[str, list[str]]:
    """Extract CVE/CWE/OWASP/vendor identifiers from a finding record.

    Called by: `normalize_findings()` so report CVE filters and finding_dedupe
    can work on Nikto output even when identifiers live in nested reference
    fields.
    """
    text = json.dumps(record, sort_keys=True, default=str)
    # Pull identifiers from the serialized record so nested reference fields are
    # covered even when Nikto changes the exact key name.
    identifiers: dict[str, list[str]] = {
        "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE))),
        "cwe": sorted(set(identifier.upper() for identifier in re.findall(r"CWE-\d+", text, re.IGNORECASE))),
        "owasp": sorted(set(re.findall(r"A\d{2}:20\d{2}", text, re.IGNORECASE))),
        "vendor": [],
    }
    nikto_id = record.get("id") or record.get("nikto_id") or record.get("test_id")
    if nikto_id:
        identifiers["vendor"].append(f"nikto:{nikto_id}")
    osvdb = record.get("OSVDB") or record.get("osvdb")
    if osvdb:
        identifiers["vendor"].append(f"osvdb:{osvdb}")
    return {key: values for key, values in identifiers.items() if values}


def stable_finding_id(target: dict[str, Any], record: dict[str, Any], message: str) -> str:
    """Return a deterministic finding ID for lifecycle correlation.

    Called by: `normalize_findings()`. The ID combines target URL, Nikto/vendor
    id, path, and message so repeated scans correlate without depending on
    Nikto output ordering.
    """
    basis = "|".join(
        [
            str(target.get("url", "")),
            str(record.get("id") or record.get("OSVDB") or record.get("osvdb") or ""),
            str(record.get("url") or record.get("uri") or record.get("path") or ""),
            message,
        ]
    )
    return f"nikto-{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:16]}"


def publish_finding(context: CommandContext, finding: dict[str, Any], *, silent: bool) -> None:
    """Publish Nikto-specific, generic, and lifecycle finding events.

    Called by: `process.run_target()` for every normalized Nikto finding.
    """
    for topic in FINDING_TOPICS:
        context.events.publish(topic, finding)
    context.alert(
        f"nikto potential finding {finding['url']} {finding['title']}",
        level="finding",
        silent=silent,
    )


def publish_tool_problem(
    context: CommandContext,
    topic: str,
    target: dict[str, Any],
    message: str,
    exc: BaseException,
    artifact_payload: dict[str, Any] | None = None,
) -> None:
    """Publish a normalized operational problem from the Nikto wrapper.

    Called by: process and artifact helpers when Nikto execution, timeout,
    output parsing, or artifact attachment fails.
    """
    context.events.publish(
        topic,
        {
            "tool": "nikto",
            "severity": "error",
            "message": message,
            "target": target,
            "exception": exc.__class__.__name__,
            "error": str(exc),
            **(artifact_payload or {}),
        },
    )
