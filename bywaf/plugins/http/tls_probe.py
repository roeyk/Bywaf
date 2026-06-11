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
    """Probe explicit or upstream TLS endpoints.

    Called by: the Bywaf runner when the `tls_probe` commandlet executes.

    Consumes: explicit `host[:port]` / HTTPS URL targets, upstream `port.open`
    events, or upstream `http.endpoint` events.

    Emits: `tls.certificate`, `tls.probe.error`, and TLS hygiene
    `finding.candidate` events.
    """
    cfg = cast(TlsProbeConfig, cfg)
    targets = tls_targets(cfg.targets, input_events, cfg.port)
    scoped_targets = filter_targets_by_host(context, targets, lambda target: target.host)

    for target in scoped_targets:
        # Check the runner cancellation flag before starting the next network
        # operation.
        context.raise_if_cancelled()

        # This records actual runtime use of the already-declared
        # `network.connect` capability.
        # Append a runtime capability-use record for this command context.
        context.audit_capability("network.connect")
        try:
            # Open a TCP/TLS connection and collect normalized certificate
            # metadata for this host/port.
            result = fetch_certificate(target.host, target.port, cfg.timeout)
        except OSError as exc:
            # Certificate capture failed before a certificate was available.
            # Persist a structured probe error instead of raising out of the
            # whole multi-target commandlet run.
            context.events.publish(
                "tls.probe.error",
                {"host": target.host, "port": target.port, "protocol": "tcp", "error": str(exc), "scanner": "tls_probe"},
            )
            continue

        # Convert normalized certificate fields into the shared typed schema
        # object, then publish its payload as the durable commandlet result.
        cert = TlsCertificate(target.host, target.port, **result, scanner="tls_probe")
        cert_payload = cert.to_payload()
        context.events.publish("tls.certificate", cert_payload)

        # Promote safe passive certificate hygiene observations into finding
        # candidates, such as expiration or hostname mismatch.
        for finding in tls_certificate_findings(cert_payload):
            context.events.publish("finding.candidate", finding)

        # Request compact operator feedback for interactive runs. The
        # structured certificate event above remains the primary output.
        context.alert(f"captured TLS certificate from {target.host}:{target.port}", silent=cfg.silent)
    return ()


class TlsProbeConfig(RunConfig):
    """Effective runtime configuration for `tls_probe`.

    Constructed by: the framework from manifest defaults plus user-supplied
    arguments/options.

    Used by: `tls_probe()` after casting the generic `RunConfig`.
    """

    targets: list[str]
    port: int | None
    silent: bool
    timeout: float


def fetch_certificate(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Return normalized TLS certificate metadata.

    Called by: `tls_probe()` once per scoped target.
    """
    # Build the stdlib TLS client context used for the handshake.
    context = ssl.create_default_context()

    # Enforce the probe's minimum TLS policy before opening the socket.
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Open a TCP connection to the target host/port.
    with socket.create_connection((host, port), timeout=timeout) as raw:
        # Wrap the TCP socket in TLS and send SNI for the probed hostname.
        with context.wrap_socket(raw, server_hostname=host) as sock:
            # Read the peer certificate as decoded stdlib certificate fields.
            cert = sock.getpeercert() or {}

            # Capture the negotiated cipher tuple; the first element is the
            # cipher suite name when negotiation succeeded.
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
    """Compact certificate name tuples into text.

    Called by: `fetch_certificate()` for certificate subject and issuer tuples.
    """
    values: list[str] = []
    if isinstance(items, tuple):
        for group in items:
            if isinstance(group, tuple):
                for pair in group:
                    if isinstance(pair, tuple) and len(pair) == 2:
                        # Convert stdlib `(name, value)` certificate pairs
                        # into compact `name=value` text.
                        values.append(f"{pair[0]}={pair[1]}")
    return ", ".join(values)


def san_values(items: object) -> list[str]:
    """Return DNS/IP subject alternative names.

    Called by: `fetch_certificate()` for `subjectAltName` certificate tuples.
    """
    values: list[str] = []
    if isinstance(items, tuple):
        for pair in items:
            if isinstance(pair, tuple) and len(pair) == 2:
                # Keep the SAN value and drop the SAN kind, matching the
                # shared `tls.certificate` schema's list-of-names field.
                values.append(str(pair[1]))
    return values


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return tls_probe


# Public re-export surface for tests, bundled plugin hydration, and legacy
# imports that reach helper functions through `bywaf.plugins.http.tls_probe`.
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
