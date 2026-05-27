"""Subject helpers for finding payloads.

Provides a small vocabulary for describing what output values are about, such
as hosts, ports, usernames, paths, finding titles, and explanatory text.

Used by:
- finding payload builders: attach `subjects` metadata to normalized findings.
- reporting/display layers: map subjects to user-configured styles."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SUBJECTS = frozenset(
    {
        "account",
        "artifact",
        "comment",
        "cve",
        "cwe",
        "email",
        "evidence",
        "explanation",
        "finding.class",
        "finding.status",
        "finding.title",
        "host",
        "ip",
        "path",
        "port",
        "protocol",
        "service",
        "severity",
        "timestamp",
        "url",
        "username",
    }
)

FIELD_SUBJECT_MAP = {
    "account": "account",
    "artifact": "artifact",
    "artifact-id": "artifact",
    "class": "finding.class",
    "comment": "comment",
    "created-at": "timestamp",
    "cve": "cve",
    "cwe": "cwe",
    "description": "explanation",
    "details": "explanation",
    "email": "email",
    "evidence": "evidence",
    "explanation": "explanation",
    "host": "host",
    "hostname": "host",
    "ip": "ip",
    "path": "path",
    "port": "port",
    "protocol": "protocol",
    "service": "service",
    "severity": "severity",
    "status": "finding.status",
    "timestamp": "timestamp",
    "title": "finding.title",
    "url": "url",
    "user": "username",
    "username": "username",
}


def subject_value(subject: str, value: Any, **metadata: Any) -> dict[str, Any]:
    """Return a typed value object for ambiguous evidence or affected entries."""
    subject = validate_subject(subject)
    payload = {"subject": subject, "value": value}
    payload.update({key: item for key, item in metadata.items() if item not in ("", None, {}, [])})
    return payload


def validate_subject(subject: str) -> str:
    """Return a normalized subject or raise for unknown subjects."""
    normalized = subject.strip().casefold().replace("_", ".")
    if normalized not in SUBJECTS:
        raise ValueError(f"unknown subject: {subject}")
    return normalized


def infer_subjects(payload: Mapping[str, Any]) -> dict[str, str]:
    """Infer subjects for canonical finding payload field paths."""
    subjects: dict[str, str] = {}
    collect_subjects(payload, prefix="", subjects=subjects)
    return subjects


def collect_subjects(value: Any, *, prefix: str, subjects: dict[str, str]) -> None:
    """Collect subjects from nested mappings and lists."""
    if isinstance(value, Mapping):
        explicit_subject = value.get("subject")
        if isinstance(explicit_subject, str) and "value" in value:
            subjects[prefix] = validate_subject(explicit_subject)
        for key, item in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            inferred = FIELD_SUBJECT_MAP.get(key_text.casefold().replace("_", "-"))
            if inferred is not None:
                subjects[path] = inferred
            collect_subjects(item, prefix=path, subjects=subjects)
    elif isinstance(value, list):
        for item in value:
            collect_subjects(item, prefix=f"{prefix}[]", subjects=subjects)


def merge_subjects(
    inferred: Mapping[str, str],
    explicit: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return inferred subjects with caller-provided overrides validated."""
    subjects = dict(inferred)
    for path, subject in (explicit or {}).items():
        subjects[str(path)] = validate_subject(str(subject))
    return subjects
