"""Finding packaging for port scanner observations.

Provides conversion from `port.open`-style payloads into normalized finding
candidates for risky exposed services such as Telnet.

Used by:
- portscanner commandlet: promote selected observations into findings.
- finding helper facade: expose legacy convenience helpers during transition."""

from __future__ import annotations

from typing import Any

from bywaf.finding import candidate_payload


def telnet_open_candidate(port_payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a finding candidate for an exposed Telnet service."""
    port = str(port_payload.get("port") or "")
    service = str(port_payload.get("service") or "").lower()
    service_detected = service == "telnet"
    default_port_heuristic = port == "23"
    if not service_detected and not default_port_heuristic:
        return None
    host = str(port_payload.get("host") or "")
    protocol = str(port_payload.get("protocol") or "tcp")
    if service_detected:
        confidence = "high"
        evidence = f"{host}:{port}/{protocol} was identified as Telnet."
    else:
        # Port 23 alone is weaker than banner/service detection. Keep it as a
        # candidate so operators can triage or confirm it later.
        confidence = "medium"
        evidence = f"{host}:{port}/{protocol} is open on the default Telnet port; confirm service identity."
    return candidate_payload(
        title="Telnet service exposed",
        finding_class="service.telnet.exposed",
        severity="medium",
        confidence=confidence,
        finding_scope="host_port",
        target={"host": host, "port": port, "protocol": protocol, "service": service or "telnet"},
        identifiers={},
        affected=[{"host": host, "port": port, "protocol": protocol}],
        evidence=evidence,
        recommendation="Disable Telnet or replace it with SSH or another encrypted management channel.",
        source={"tool": port_payload.get("scanner") or "portscanner", "topic": "port.open"},
    )
