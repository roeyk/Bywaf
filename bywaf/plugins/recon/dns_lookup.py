"""DNS lookup commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Resolves DNS records and emits host or observation events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import importlib
from collections.abc import Iterable
from typing import Any, cast

from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    RunConfig,
    commandlet,
)


@commandlet
def dns_lookup(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Resolve one or more names and publish DNS records."""
    del input_events
    cfg = cast(DnsLookupConfig, cfg)
    resolver_mod = optional_module(context, "dns.resolver", "dnspython")
    if resolver_mod is None:
        return ()
    resolver = resolver_mod.Resolver()
    resolver.lifetime = cfg.timeout
    resolver.timeout = cfg.timeout
    if cfg.resolver:
        # A user-specified resolver applies only to this invocation; it is
        # not written back to global resolver configuration.
        resolver.nameservers = [cfg.resolver]
    for name in cfg.names:
        context.audit_capability("network.connect")
        try:
            answer = resolver.resolve(name, cfg.record_type)
        except Exception as exc:
            context.events.publish(
                "dns.error",
                {"name": name, "record_type": cfg.record_type, "error": str(exc)},
            )
            continue
        for record in answer:
            context.events.publish(
                "dns.record",
                {"name": name, "record_type": cfg.record_type, "value": record.to_text()},
            )
    return ()


class DnsLookupConfig(RunConfig):
    """Typed effective config for dns_lookup."""

    names: list[str]
    record_type: str
    resolver: str
    timeout: float


def optional_module(context: CommandContext, module_name: str, package_name: str) -> Any | None:
    """Import an optional library or publish a tool error."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
        # Optional integrations should fail as data, not as an import traceback,
        # so pipelines can continue and the report can explain the gap.
        context.events.publish(
            "tool.error",
            {
                "tool": package_name,
                "severity": "error",
                "message": f"missing optional Python package: {package_name}",
            },
        )
        return None


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return dns_lookup
