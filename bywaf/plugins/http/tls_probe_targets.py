"""Target resolution helpers for the TLS probe commandlet."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

from bywaf.event import Event
from bywaf.event.schema_objects import HttpEndpoint, OpenPort


@dataclass(frozen=True, slots=True)
class TlsTarget:
    """One TLS endpoint to probe.

    Constructed by: `target_from_text()` and `tls_targets()`.
    Used by: `tls_probe.tls_probe()` before network connection attempts.
    """

    host: str
    port: int


def tls_targets(targets: list[str], input_events: Iterable[Event], default_port: int | None) -> list[TlsTarget]:
    """Resolve TLS probe targets from args or upstream events.

    Called by: `tls_probe.tls_probe()`.
    """
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
            if port.protocol == "tcp" and _looks_tls_capable(port.port, port.service):
                resolved.append(TlsTarget(port.host, port.port))
    return list(dict.fromkeys(resolved))


def target_from_text(target: str, default_port: int) -> TlsTarget:
    """Parse host[:port] into a TLS target.

    Called by: `tls_targets()` when the operator passes explicit targets.
    """
    if "://" in target:
        parsed = urlparse(target)
        return TlsTarget(parsed.hostname or "", parsed.port or 443)
    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        return TlsTarget(host, int(port))
    return TlsTarget(target.strip("[]"), default_port)


def _looks_tls_capable(port: int, service: object) -> bool:
    """Return whether an open-port fact is worth probing for TLS.

    Called by: `tls_targets()` for upstream `port.open` facts.
    """
    service_text = str(service or "").casefold()
    return port in {443, 8443} or "ssl" in service_text or "https" in service_text
