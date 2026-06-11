"""Safe TLS certificate hygiene finding synthesis."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bywaf.finding import candidate_payload


def tls_certificate_findings(cert: dict[str, Any], *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Return safe TLS hygiene finding candidates from certificate metadata.

    Called by: `tls_probe.tls_probe()` after certificate capture.
    """
    findings: list[dict[str, Any]] = []
    host = str(cert.get("host") or "")
    port = int(cert.get("port") or 443)
    not_after = parse_tls_time(str(cert.get("not_after") or ""))
    now = now or datetime.now(UTC)
    if not_after is not None and not_after < now:
        findings.append(_expired_certificate_finding(cert, host=host, port=port))
    if host and not certificate_matches_host(host, cert):
        findings.append(_hostname_mismatch_finding(host=host, port=port))
    return findings


def parse_tls_time(value: str) -> datetime | None:
    """Parse common TLS certificate timestamps.

    Called by: `tls_certificate_findings()`.
    """
    if not value:
        return None
    for pattern in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def certificate_matches_host(host: str, cert: dict[str, Any]) -> bool:
    """Return whether certificate SAN or subject covers the probed host.

    Called by: `tls_certificate_findings()`.
    """
    names = [str(name).casefold() for name in cert.get("san") or []]
    subject = str(cert.get("subject") or "")
    for part in subject.split(","):
        key, _, value = part.strip().partition("=")
        if key.casefold() in {"commonname", "cn"} and value:
            names.append(value.casefold())
    if not names:
        return True
    return any(host_matches_name(host.casefold(), name) for name in names)


def host_matches_name(host: str, name: str) -> bool:
    """Return whether a DNS name or one-label wildcard matches a host.

    Called by: `certificate_matches_host()`.
    """
    if name == host:
        return True
    if not name.startswith("*."):
        return False
    suffix = name[1:]
    return host.endswith(suffix) and host.count(".") == suffix.count(".")


def _expired_certificate_finding(cert: dict[str, Any], *, host: str, port: int) -> dict[str, Any]:
    """Return the expired-certificate candidate used by `tls_certificate_findings()`."""
    return candidate_payload(
        title="Expired TLS certificate",
        finding_class="service.tls.certificate_expired",
        severity="medium",
        confidence="high",
        confidence_basis="safe_probe",
        target={"host": host, "port": port, "protocol": "tcp"},
        target_scope={"kind": "service", "value": f"{host}:{port}/tcp"},
        affected=[{"host": host, "port": port}],
        evidence=f"Certificate not_after is {cert.get('not_after')}",
        recommendation="Renew or replace the certificate and retest the TLS endpoint.",
        source={"tool": "tls_probe", "topic": "tls.certificate"},
    )


def _hostname_mismatch_finding(*, host: str, port: int) -> dict[str, Any]:
    """Return the hostname-mismatch candidate used by `tls_certificate_findings()`."""
    return candidate_payload(
        title="TLS certificate hostname mismatch",
        finding_class="service.tls.hostname_mismatch",
        severity="medium",
        confidence="high",
        confidence_basis="safe_probe",
        target={"host": host, "port": port, "protocol": "tcp"},
        target_scope={"kind": "service", "value": f"{host}:{port}/tcp"},
        affected=[{"host": host, "port": port}],
        evidence=f"Certificate SAN/subject does not match {host}",
        recommendation="Install a certificate whose SAN covers the probed hostname.",
        source={"tool": "tls_probe", "topic": "tls.certificate"},
    )
