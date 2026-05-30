"""DNS enumeration commandlet.

Resolves a small hostname/subdomain set with the system resolver and emits
shared host/name facts for downstream scanners.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable
from typing import cast

from bywaf.event_schema_objects import HostFound, NameResolved
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet, split_var_values


@commandlet
def dns_enum(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Resolve explicit names or endpoint hosts into host facts."""
    del input_events
    cfg = cast(DnsEnumConfig, cfg)
    for name in dns_targets(cfg.names, cfg.domain, cfg.words):
        context.audit_capability("network.connect")
        try:
            addresses = resolve_name(name)
        except OSError as exc:
            context.events.publish("dns.error", {"name": name, "record_type": "A", "error": str(exc)})
            continue
        for address in addresses:
            context.events.publish("name.resolved", NameResolved(name, address, resolver="system").to_payload())
            context.events.publish("host.found", HostFound(address, name=name, status="reachable", scanner="dns_enum").to_payload())
            context.alert(f"resolved {name} -> {address}", silent=cfg.silent)
    return ()


class DnsEnumConfig(RunConfig):
    """Typed effective config for dns_enum."""

    names: list[str]
    domain: str
    words: str
    silent: bool


def dns_targets(names: list[str], domain: str, words: str) -> list[str]:
    """Return unique names from explicit args or wordlist + domain."""
    targets = list(names)
    if domain and words:
        targets.extend(f"{word}.{domain}" for word in split_var_values(words))
    return list(dict.fromkeys(target for target in targets if target))


def resolve_name(name: str) -> list[str]:
    """Resolve one DNS name with the system resolver."""
    addresses = {
        info[4][0]
        for info in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    }
    return sorted(addresses)


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return dns_enum
