"""TLS probing commandlet."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from bywaf.event.schema_objects import HttpEndpoint, OpenPort, TlsCertificate
from bywaf.event import Event
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
        context.events.publish("tls.certificate", cert.to_payload())
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


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return tls_probe
