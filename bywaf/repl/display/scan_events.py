"""Compact display renderers for scan and finding events.

Used by:
- interactive REPL commands, app-dispatch helpers, and display tests.
- operators who inspect runtime state through built-in commands.
"""

from __future__ import annotations

from ...runner import Runner
from .variables import subject_text


def format_finding_event(event, runner: Runner | None = None) -> str:
    """Render a finding payload without dumping the full report structure."""
    payload = event.payload
    title = payload.get("title") or payload.get("class") or "finding"
    target = format_finding_target(payload, runner)
    severity = payload.get("severity", "")
    status = payload.get("status", "")
    basis = payload.get("confidence_basis") or payload.get("confidence", "")
    details = " ".join(str(value) for value in (target, severity, status, basis) if value)
    suffix = f" {details}" if details else ""
    return f"{event.id}: {event.topic} {title}{suffix}".strip()


def format_merge_candidate_event(event, runner: Runner | None = None) -> str:
    """Render a merge candidate as a compact finding comparison hint."""
    payload = event.payload
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        return format_finding_event(event, runner)
    title = candidate.get("title") or candidate.get("class") or "finding"
    target = format_finding_target(candidate, runner)
    existing_id = payload.get("existing_finding_id")
    existing_text = f" existing={existing_id}" if existing_id is not None else ""
    target_text = f" {target}" if target else ""
    return f"{event.id}: finding.merge_candidate {title}{target_text}{existing_text}".strip()


def format_finding_target(payload: dict[str, object], runner: Runner | None = None) -> str:
    """Return the most useful short target text from a finding payload."""
    target = payload.get("target")
    if isinstance(target, dict):
        if target.get("url"):
            return subject_text(runner, "url", target["url"])
        host = target.get("host")
        if host:
            host_text = subject_text(runner, "host", host)
            port = target.get("port")
            scheme = target.get("scheme")
            if port:
                port_text = subject_text(runner, "port", port)
                scheme_text = f"{scheme}://" if scheme else ""
                return f"{scheme_text}{host_text}:{port_text}"
            return host_text
    affected = payload.get("affected")
    if isinstance(affected, list) and affected:
        first = affected[0]
        if isinstance(first, dict):
            if first.get("url"):
                return subject_text(runner, "url", first["url"])
            if first.get("host"):
                return subject_text(runner, "host", first["host"])
    return ""


def format_http_headers_event(event, runner: Runner | None = None) -> str:
    """Render observed HTTP headers as a small response summary."""
    payload = event.payload
    host = subject_text(runner, "host", payload.get("host", ""))
    port = subject_text(runner, "port", payload.get("port", ""))
    status = payload.get("status", "")
    headers = payload.get("headers", {})
    header_text = format_limited_list(headers) if isinstance(headers, dict) else ""
    status_text = f" status={status}" if status != "" else ""
    header_suffix = f" headers={header_text}" if header_text else ""
    return f"{event.id}: http.headers {host}:{port}{status_text}{header_suffix}".strip()


def format_tls_certificate_event(event, runner: Runner | None = None) -> str:
    """Render TLS certificate metadata without dumping the full payload."""
    payload = event.payload
    host = subject_text(runner, "host", payload.get("host", ""))
    port = subject_text(runner, "port", payload.get("port", ""))
    san_text = format_limited_list(payload.get("san", []), limit=3)
    details = " ".join(
        part
        for part in (
            f"subject={payload.get('subject')}" if payload.get("subject") else "",
            f"issuer={payload.get('issuer')}" if payload.get("issuer") else "",
            f"not_after={payload.get('not_after')}" if payload.get("not_after") else "",
            f"san={san_text}" if san_text else "",
        )
        if part
    )
    suffix = f" {details}" if details else ""
    return f"{event.id}: tls.certificate {host}:{port}{suffix}".strip()


def format_tls_error_event(event, runner: Runner | None = None) -> str:
    """Render TLS probe failures as compact endpoint errors."""
    payload = event.payload
    host = subject_text(runner, "host", payload.get("host", ""))
    port = subject_text(runner, "port", payload.get("port", ""))
    error = payload.get("error", "")
    error_text = f" error={error}" if error else ""
    return f"{event.id}: tls.probe.error {host}:{port}{error_text}".strip()


def format_limited_list(value: object, *, limit: int = 5) -> str:
    """Return a compact sorted-list summary for mappings or sequences."""
    if isinstance(value, dict):
        items = sorted(str(name) for name in value)
    elif isinstance(value, list | tuple):
        items = [str(item) for item in value]
    else:
        return ""
    if not items:
        return ""
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    if extra > 0:
        return f"{shown}, +{extra} more"
    return shown
