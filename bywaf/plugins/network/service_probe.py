"""Service classification commandlet.

Converts port, banner, HTTP, and TLS facts into a common `service.detected`
view for downstream reporting and follow-up plugins.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from bywaf.event.schema_objects import HttpEndpoint, OpenPort, ServiceDetected, TcpBanner, TlsCertificate
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet


@commandlet
def service_probe(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Classify upstream service observations."""
    cfg = cast(ServiceProbeConfig, cfg)
    for event in input_events:
        service = service_from_event(event)
        if service is None:
            continue
        context.events.publish("service.detected", service.to_payload())
        context.alert(f"detected service {service.service} on {service.host}:{service.port}/{service.protocol}", silent=cfg.silent)
    return ()


class ServiceProbeConfig(RunConfig):
    """Typed effective config for service_probe."""

    silent: bool


def service_from_event(event: Event) -> ServiceDetected | None:
    """Return a service fact from one upstream event."""
    if event.topic == OpenPort.__topic__:
        port = OpenPort.from_event(event)
        service = port.service or known_service(port.port, port.protocol)
        return ServiceDetected(port.host, port.port, port.protocol, service or "unknown", source="port.open", confidence="medium")
    if event.topic == TcpBanner.__topic__:
        banner = TcpBanner.from_event(event)
        return ServiceDetected(
            banner.host,
            banner.port,
            banner.protocol,
            classify_banner(banner.banner or "") or known_service(banner.port, banner.protocol) or "unknown",
            source="tcp.banner",
            confidence="high" if banner.banner else "low",
            evidence=banner.banner or banner.error,
        )
    if event.topic == HttpEndpoint.__topic__:
        endpoint = HttpEndpoint.from_event(event)
        return ServiceDetected(endpoint.host, endpoint.port, "tcp", endpoint.scheme, source="http.endpoint", confidence="high", evidence=endpoint.server)
    if event.topic == TlsCertificate.__topic__:
        cert = TlsCertificate.from_event(event)
        return ServiceDetected(cert.host, cert.port, "tcp", "tls", source="tls.certificate", confidence="high", evidence=cert.subject)
    return None


def known_service(port: int, protocol: str) -> str:
    """Return common service labels for well-known ports."""
    if protocol != "tcp":
        return ""
    return {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "smb",
        993: "imaps",
        995: "pop3s",
        2375: "docker",
        2376: "docker",
        3389: "rdp",
        5601: "kibana",
        5985: "winrm",
        5986: "winrm",
        6379: "redis",
        6443: "kubernetes",
        8443: "https-alt",
        9090: "prometheus",
        9200: "elasticsearch",
        9300: "elasticsearch",
        10250: "kubelet",
        11211: "memcached",
        27017: "mongodb",
    }.get(port, "")


def classify_banner(banner: str) -> str:
    """Infer a service label from a banner."""
    lowered = banner.casefold()
    if lowered.startswith("ssh-"):
        return "ssh"
    if lowered.startswith("http/") or "server:" in lowered:
        return "http"
    if "smtp" in lowered:
        return "smtp"
    if "ftp" in lowered:
        return "ftp"
    if "redis_version" in lowered or lowered.startswith("-redis"):
        return "redis"
    if "memcached" in lowered:
        return "memcached"
    if "mongodb" in lowered:
        return "mongodb"
    if "elasticsearch" in lowered or "opensearch" in lowered:
        return "elasticsearch"
    return ""


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return service_probe
