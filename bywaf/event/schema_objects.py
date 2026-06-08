"""Typed objects for framework-known shared event schemas.

Provides small dataclasses that plugin authors can import instead of defining
their own wrappers around common shared event payloads.

Used by:
- plugin authors: deserialize shared events into typed objects.
- tests and docs: demonstrate object-first schema object handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .schemas import EventSchemaObject


@dataclass(frozen=True)
class HostFound(EventSchemaObject):
    """A host observed alive or otherwise reachable.

    This represents the canonical host discovery fact.
    Constructed by: discovery plugins before publishing `host.found`.
    Used by: inventory, report synthesis, and runtime event display.
    """

    __topic__ = "host.found"

    host: str
    ip: str | None = None
    name: str | None = None
    status: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class NameResolved(EventSchemaObject):
    """One hostname-to-address resolution fact.

    This links a name to the host address that resolved from it.
    Constructed by: DNS-aware plugins before publishing `name.resolved`.
    Used by: inventory and network report synthesis.
    """

    __topic__ = "name.resolved"

    name: str
    host: str
    resolver: str | None = None


@dataclass(frozen=True)
class OpenPort(EventSchemaObject):
    """A network port observed open on a host.

    This represents the canonical open-port observation.
    Constructed by: port scanners before publishing `port.open`.
    Used by: service inventory, report synthesis, event display, and follow-up
    service probes.
    """

    __topic__ = "port.open"

    host: str
    port: int
    protocol: str
    state: str | None = None
    service: str | None = None
    reason: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class HttpEndpoint(EventSchemaObject):
    """A reachable HTTP or HTTPS endpoint.

    This represents a normalized web origin/path that responded or failed.
    Constructed by: HTTP probing plugins before publishing `http.endpoint`.
    Used by: web inventory, reporting, and downstream HTTP analysis plugins.
    """

    __topic__ = "http.endpoint"

    url: str
    host: str
    port: int
    scheme: str
    status: int | None = None
    method: str | None = None
    server: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ScreenshottedHost(EventSchemaObject):
    """One host or endpoint with one or more screenshot artifact references.

    This ties web visual evidence to a host or URL.
    Constructed by: screenshot plugins before publishing
    `web.screenshotted_host`.
    Used by: web inventory and reports.
    """

    __topic__ = "web.screenshotted_host"

    host: str
    urls: list[str]
    screenshots: list[dict[str, Any]]
    tool: str | None = None


@dataclass(frozen=True)
class TcpBanner(EventSchemaObject):
    """A TCP service banner or first response.

    This represents raw-but-bounded service identity evidence.
    Constructed by: banner-grabbing plugins before publishing `tcp.banner`.
    Used by: service detection, technology indicators, reports, and event
    display.
    """

    __topic__ = "tcp.banner"

    host: str
    port: int
    protocol: str = "tcp"
    banner: str | None = None
    error: str | None = None
    elapsed_ms: int | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class ServiceDetected(EventSchemaObject):
    """A normalized service classification for a host/port.

    This represents a tool-neutral service identity.
    Constructed by: port scanners and service probes before publishing
    `service.detected`.
    Used by: inventory, reports, and pipeline consumers.
    """

    __topic__ = "service.detected"

    host: str
    port: int
    protocol: str
    service: str
    product: str | None = None
    version: str | None = None
    source: str | None = None
    confidence: str | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class TlsCertificate(EventSchemaObject):
    """TLS certificate metadata observed from a network service.

    This represents inspectable certificate metadata, not the raw certificate.
    Constructed by: TLS probing plugins before publishing `tls.certificate`.
    Used by: certificate inventory, reports, event display, and expiration
    checks.
    """

    __topic__ = "tls.certificate"

    host: str
    port: int
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: list[str] | None = None
    protocol: str | None = None
    cipher: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class HttpPathObserved(EventSchemaObject):
    """One HTTP path response observed during path probing.

    This represents a probed URL path and response metadata.
    Constructed by: path discovery plugins before publishing `http.path`.
    Used by: web inventory, path-finding analysis, reports, and follow-up
    checks.
    """

    __topic__ = "http.path"

    url: str
    host: str
    port: int
    path: str
    status: int | None = None
    title: str | None = None
    content_type: str | None = None
    length: int | None = None
    interesting: bool | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class WebWafDetected(EventSchemaObject):
    """A WAF or edge protection product fingerprint.

    This represents edge-protection evidence for a web target.
    Constructed by: WAF-detection plugins before publishing
    `web.waf.detected`.
    Used by: web inventory, reports, and finding logic.
    """

    __topic__ = "web.waf.detected"

    url: str
    host: str
    vendor: str
    product: str | None = None
    evidence: str | None = None
    confidence: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class NetworkRouteHop(EventSchemaObject):
    """One hop observed while tracing a route to a target.

    This represents one hop in a path observation.
    Constructed by: traceroute-style plugins before publishing
    `network.route.hop`.
    Used by: network inventory and reports.
    """

    __topic__ = "network.route.hop"

    target: str
    hop: int
    host: str | None = None
    ip: str | None = None
    rtt_ms: float | None = None
    status: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class SmbShareFound(EventSchemaObject):
    """An SMB share observed on a host.

    This represents share exposure evidence.
    Constructed by: SMB enumeration plugins before publishing
    `smb.share.found`.
    Used by: inventory, finding logic, and reports.
    """

    __topic__ = "smb.share.found"

    host: str
    share: str
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    access: str | None = None
    authenticated: bool | None = None
    remark: str | None = None


@dataclass(frozen=True)
class ArtifactAttached(EventSchemaObject):
    """Artifact metadata attached to runtime provenance.

    This represents artifact metadata without embedding artifact contents.
    Constructed by: commandlets and artifact services before publishing
    `artifact.attached`.
    Used by: bundle, audit, report, and runtime artifact views.
    """

    __topic__ = "artifact.attached"

    artifact_id: str
    name: str
    content_type: str
    sha256: str
    size: int
    commandlet: str | None = None
    job_id: Any = None
    pipeline_id: str | None = None
    command_run_id: str | None = None
    note: str | None = None


def parse_tls_not_after(value: str | None) -> datetime | None:
    """Parse common certificate notAfter text into UTC datetime."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return None


__all__ = [
    "ArtifactAttached",
    "HostFound",
    "HttpEndpoint",
    "HttpPathObserved",
    "NameResolved",
    "NetworkRouteHop",
    "OpenPort",
    "parse_tls_not_after",
    "ScreenshottedHost",
    "ServiceDetected",
    "SmbShareFound",
    "TcpBanner",
    "TlsCertificate",
    "WebWafDetected",
]
