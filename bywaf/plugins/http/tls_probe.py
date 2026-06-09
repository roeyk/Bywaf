"""TLS probing commandlet."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable
from typing import Any, cast

from bywaf.event import Event
from bywaf.event.schema_objects import TlsCertificate
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.plugins.target_policy import filter_targets_by_host

from .tls_probe_findings import certificate_matches_host, host_matches_name, parse_tls_time, tls_certificate_findings
from .tls_probe_targets import TlsTarget, target_from_text, tls_targets


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


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return tls_probe


__all__ = [
    "TlsProbeConfig",
    "TlsTarget",
    "certificate_matches_host",
    "fetch_certificate",
    "host_matches_name",
    "name_values",
    "parse_tls_time",
    "plugin",
    "san_values",
    "target_from_text",
    "tls_certificate_findings",
    "tls_probe",
    "tls_targets",
]
