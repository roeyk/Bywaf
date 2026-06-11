"""Shared network service naming helpers.

Provides lightweight service-name inference for plugins that need to turn
ports, protocols, and banners into normalized service labels.

Used by:
- `plugins.network.service_probe`: converts upstream facts into
  `service.detected` events.
- future network and report plugins that need a common service vocabulary
  without duplicating port tables or banner classifiers.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass


# Classification table for Bywaf-specific service labels.
#
# Used by: `known_service()`, before the stdlib service database is consulted.
# The override layer keeps product/security names stable where the OS service
# database uses less helpful labels, and it covers high-value management ports
# that may not be present in every `/etc/services`.
SERVICE_OVERRIDES: dict[tuple[str, int], str] = {
    ("tcp", 53): "dns",
    ("udp", 53): "dns",
    ("tcp", 2375): "docker",
    ("tcp", 2376): "docker",
    ("tcp", 5601): "kibana",
    ("tcp", 5985): "winrm",
    ("tcp", 5986): "winrm",
    ("tcp", 6443): "kubernetes",
    ("tcp", 8443): "https-alt",
    ("tcp", 9090): "prometheus",
    ("tcp", 9200): "elasticsearch",
    ("tcp", 9300): "elasticsearch",
    ("tcp", 10250): "kubelet",
    ("tcp", 27017): "mongodb",
    ("udp", 161): "snmp",
    ("udp", 162): "snmptrap",
}


def known_service(port: int, protocol: str) -> str:
    """Return a normalized service label for a port/protocol pair.

    Called by: service-classification plugins before they fall back to
    `unknown`.

    The lookup first applies Bywaf's small security-oriented override table,
    then asks Python's stdlib service database through `socket.getservbyport`.
    That gives us TCP and UDP coverage without maintaining a full local copy of
    `/etc/services`.
    """

    normalized_protocol = protocol.casefold()
    override = SERVICE_OVERRIDES.get((normalized_protocol, port))
    if override is not None:
        return override

    try:
        return socket.getservbyport(port, normalized_protocol)
    except OSError:
        return ""


@dataclass(frozen=True, slots=True)
class BannerRule:
    """One banner-to-service classification rule.

    Constructed by: the module-level `BANNER_RULES` classification table.

    Used by: `classify_banner()` to avoid hard-coded if/elif banner ladders in
    plugins.
    """

    service: str
    matches: Callable[[str], bool]


def starts_with(*prefixes: str) -> Callable[[str], bool]:
    """Build a banner predicate for protocol greeting prefixes."""

    return lambda banner: any(banner.startswith(prefix) for prefix in prefixes)


def contains_any(*needles: str) -> Callable[[str], bool]:
    """Build a banner predicate for product strings embedded in banner text."""

    return lambda banner: any(needle in banner for needle in needles)


def http_banner(banner: str) -> bool:
    """Return whether a banner looks like an HTTP status/header response."""

    return banner.startswith("http/") or "server:" in banner


# Ordered banner classification table.
#
# Used by: `classify_banner()`, which returns the first matching service. Rules
# stay as data so plugins can extend or audit them without editing control-flow
# ladders.
BANNER_RULES = (
    BannerRule("ssh", starts_with("ssh-")),
    BannerRule("http", http_banner),
    BannerRule("smtp", contains_any("smtp")),
    BannerRule("ftp", contains_any("ftp")),
    BannerRule("redis", lambda banner: "redis_version" in banner or banner.startswith("-redis")),
    BannerRule("memcached", contains_any("memcached")),
    BannerRule("mongodb", contains_any("mongodb")),
    BannerRule("elasticsearch", contains_any("elasticsearch", "opensearch")),
)


def classify_banner(banner: str) -> str:
    """Infer a service label from protocol or product banner text.

    Called by: service-classification plugins when a richer banner signal is
    available than a port-number heuristic.
    """

    normalized_banner = banner.casefold()
    for rule in BANNER_RULES:
        if rule.matches(normalized_banner):
            return rule.service
    return ""
