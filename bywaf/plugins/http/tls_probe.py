"""TLS probing commandlet."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from bywaf.event.schema_objects import HttpEndpoint, OpenPort, TlsCertificate
from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.plugins.target_policy import filter_targets_by_host


@commandlet
def tls_probe(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Probe explicit or upstream TLS endpoints."""
    cfg = cast(TlsProbeConfig, cfg)
    for target in filter_targets_by_host(context, tls_targets(cfg.targets, input_events, cfg.port), lambda target: target.host):
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
        try:
            result = fetch_certificate(target.host, target.port, cfg.timeout)
        except OSError as exc:
            context.events.publish(
                "tls.probe.error",
                {"host": target.host, "port": target.port, "protocol": "tcp", "error": str(exc), "scanner": "tls_probe"},
            )
            continue
        cert = TlsCertificate(target.host, target.port, **result, scanner="tls_probe")
        cert_payload = cert.to_payload()
        context.events.publish("tls.certificate", cert_payload)
        for finding in tls_certificate_findings(cert_payload):
            context.events.publish("finding.candidate", finding)
        context.alert(f"captured TLS certificate from {target.host}:{target.port}", silent=cfg.silent)
    return ()


class TlsProbeConfig(RunConfig):
    """Typed effective config for tls_probe."""

    targets: list[str]
    port: int | None
    silent: bool
    timeout: float


@dataclass(frozen=True, slots=True)
class TlsTarget:
    """One TLS endpoint to probe."""

    host: str
    port: int


def tls_targets(targets: list[str], input_events: Iterable[Event], default_port: int | None) -> list[TlsTarget]:
    """Resolve TLS probe targets from args or upstream events."""
    if targets:
        return [target_from_text(target, default_port or 443) for target in targets]
    resolved: list[TlsTarget] = []
    for event in input_events:
        if event.topic == HttpEndpoint.__topic__:
            endpoint = HttpEndpoint.from_event(event)
            if endpoint.scheme == "https":
                resolved.append(TlsTarget(endpoint.host, endpoint.port))
        elif event.topic == OpenPort.__topic__:
            port = OpenPort.from_event(event)
            if port.protocol == "tcp" and (port.port in {443, 8443} or "ssl" in str(port.service or "").casefold() or "https" in str(port.service or "").casefold()):
                resolved.append(TlsTarget(port.host, port.port))
    return list(dict.fromkeys(resolved))


def target_from_text(target: str, default_port: int) -> TlsTarget:
    """Parse host[:port] into a TLS target."""
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        return TlsTarget(parsed.hostname or "", parsed.port or 443)
    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        return TlsTarget(host, int(port))
    return TlsTarget(target.strip("[]"), default_port)


def fetch_certificate(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Return normalized TLS certificate metadata."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            cert = sock.getpeercert() or {}
            cipher = sock.cipher()
            return {
                "subject": name_values(cert.get("subject", ())),
                "issuer": name_values(cert.get("issuer", ())),
                "not_before": str(cert.get("notBefore") or ""),
                "not_after": str(cert.get("notAfter") or ""),
                "san": san_values(cert.get("subjectAltName", ())),
                "protocol": sock.version() or "",
                "cipher": cipher[0] if cipher else "",
            }


def name_values(items: object) -> str:
    """Compact certificate name tuples into text."""
    values: list[str] = []
    if isinstance(items, tuple):
        for group in items:
            if isinstance(group, tuple):
                for pair in group:
                    if isinstance(pair, tuple) and len(pair) == 2:
                        values.append(f"{pair[0]}={pair[1]}")
    return ", ".join(values)


def san_values(items: object) -> list[str]:
    """Return DNS/IP subject alternative names."""
    values: list[str] = []
    if isinstance(items, tuple):
        for pair in items:
            if isinstance(pair, tuple) and len(pair) == 2:
                values.append(str(pair[1]))
    return values


def tls_certificate_findings(cert: dict[str, Any], *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Return safe TLS hygiene finding candidates from certificate metadata."""
    findings: list[dict[str, Any]] = []
    host = str(cert.get("host") or "")
    port = int(cert.get("port") or 443)
    not_after = parse_tls_time(str(cert.get("not_after") or ""))
    now = now or datetime.now(UTC)
    if not_after is not None and not_after < now:
        findings.append(
            candidate_payload(
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
        )
    if host and not certificate_matches_host(host, cert):
        findings.append(
            candidate_payload(
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
        )
    return findings


def parse_tls_time(value: str) -> datetime | None:
    """Parse common TLS certificate timestamps."""
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
    """Return whether certificate SAN or subject covers the probed host."""
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
    """Return whether a DNS name or one-label wildcard matches a host."""
    if name == host:
        return True
    if not name.startswith("*."):
        return False
    suffix = name[1:]
    return host.endswith(suffix) and host.count(".") == suffix.count(".")


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return tls_probe
