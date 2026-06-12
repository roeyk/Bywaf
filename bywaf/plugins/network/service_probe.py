"""Service classification commandlet.

Converts port, banner, HTTP, and TLS facts into a common `service.detected`
view for downstream reporting and follow-up plugins.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from bywaf.event.schema_objects import HttpEndpoint, OpenPort, ServiceDetected, TcpBanner, TlsCertificate
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.service_names import classify_banner, known_service


@commandlet
def service_probe(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Classify upstream service observations.

    Called by: the Bywaf runner when the `service_probe` commandlet executes.

    Consumes: passive upstream facts such as `port.open`, `tcp.banner`,
    `http.endpoint`, and `tls.certificate`.

    Emits: normalized `service.detected` facts for inventory, reports,
    technology indicators, and downstream analysis plugins.
    """

    # The framework passes plugin config through the generic RunConfig type.
    # This cast names the concrete config fields this commandlet uses.
    cfg = cast(ServiceProbeConfig, cfg)

    for event in input_events:
        # Convert each supported upstream event into a neutral service fact.
        # Unsupported topics return None and are ignored.
        service = service_from_event(event)
        if service is None:
            continue

        # The structured event is the durable output. The alert is only
        # operator-facing feedback for the current run and can be silenced.
        context.events.publish("service.detected", service.to_payload())
        context.alert(f"detected service {service.service} on {service.host}:{service.port}/{service.protocol}", silent=cfg.silent)
    return ()


class ServiceProbeConfig(RunConfig):
    """Plugin-specific effective configuration for `service_probe`.

    Constructed by: the framework when it hydrates manifest defaults and
    operator arguments for this commandlet run.

    Used by: `service_probe()` to decide whether operator-facing alerts should
    be suppressed.
    """

    silent: bool


def service_from_event(event: Event) -> ServiceDetected | None:
    """Return a normalized service fact from one upstream event.

    Called by: `service_probe()` for every pipeline input event.

    The function is deliberately pure with respect to framework state. It does
    not publish or alert, which keeps unit tests focused on classification
    behavior and lets the commandlet own side effects in one place.
    """

    if event.topic == OpenPort.__topic__:
        # Port scanners may already know the service. If they do not, use the
        # shared service-name helper, which now handles both TCP and UDP.
        port = OpenPort.from_event(event)
        service = port.service or known_service(port.port, port.protocol)
        return ServiceDetected(port.host, port.port, port.protocol, service or "unknown", source="port.open", confidence="medium")

    if event.topic == TcpBanner.__topic__:
        # Banners are stronger evidence than port numbers, so classify banner
        # text first and fall back to well-known port lookup only when needed.
        banner = TcpBanner.from_event(event)
        # Prefer the banner classifier, then fall back to the port/protocol
        # service lookup, then use `unknown` when neither source can identify
        # the service.
        service = classify_banner(banner.banner or "") or known_service(banner.port, banner.protocol) or "unknown"
        return ServiceDetected(
            banner.host,
            banner.port,
            banner.protocol,
            service,
            source="tcp.banner",
            confidence="high" if banner.banner else "low",
            evidence=banner.banner or banner.error,
        )

    if event.topic == HttpEndpoint.__topic__:
        # HTTP endpoint facts already identify the application protocol and
        # carry optional server evidence from earlier HTTP probing.
        endpoint = HttpEndpoint.from_event(event)
        return ServiceDetected(endpoint.host, endpoint.port, "tcp", endpoint.scheme, source="http.endpoint", confidence="high", evidence=endpoint.server)

    if event.topic == TlsCertificate.__topic__:
        # A certificate proves a TLS-speaking service even when the exact
        # application protocol above TLS remains unknown.
        cert = TlsCertificate.from_event(event)
        return ServiceDetected(cert.host, cert.port, "tcp", "tls", source="tls.certificate", confidence="high", evidence=cert.subject)

    return None


def plugin() -> Commandlet:
    """Return the commandlet factory object used by PluginRegistry."""

    return service_probe
