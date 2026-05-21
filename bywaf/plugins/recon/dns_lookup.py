"""DNS lookup commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Resolves DNS records and emits host or observation events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import importlib
from collections.abc import Iterable
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options

DEFAULTS = {"record-type": "A", "resolver": "", "timeout": "5"}
OPTION_KEYS = {"record-type", "resolver", "timeout"}


@commandlet(
    name="dns_lookup",
    description="Resolve DNS records with dnspython.",
    usage="dns_lookup [record-type=TYPE] [resolver=IP] <name ...>",
    examples=("dns_lookup example.com", "dns_lookup record-type=MX example.com"),
    emits=("dns.record", "dns.error"),
    capabilities=("db.write:dns.record", "db.write:dns.error", "network.connect"),
)
@option("record-type", "DNS record type", "A")
@option("resolver", "resolver IP address")
@option("timeout", "DNS timeout seconds", "5")
class DnsLookup(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Resolve one or more names and publish DNS records."""
        del input_events
        parser = self.parser()
        parser.add_argument("names", nargs="+")
        parser.add_argument("--record-type", default=self.var_default(context, "record-type", "A"))
        parser.add_argument("--resolver", default=self.var_default(context, "resolver", ""))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        resolver_mod = optional_module(context, "dns.resolver", "dnspython")
        if resolver_mod is None:
            return ()
        resolver = resolver_mod.Resolver()
        resolver.lifetime = parsed.timeout
        resolver.timeout = parsed.timeout
        if parsed.resolver:
            resolver.nameservers = [parsed.resolver]
        for name in parsed.names:
            context.audit_capability("network.connect")
            try:
                answer = resolver.resolve(name, parsed.record_type)
            except Exception as exc:
                context.events.publish(
                    "dns.error",
                    {"name": name, "record_type": parsed.record_type, "error": str(exc)},
                )
                continue
            for record in answer:
                context.events.publish(
                    "dns.record",
                    {"name": name, "record_type": parsed.record_type, "value": record.to_text()},
                )
        return ()


def optional_module(context: CommandContext, module_name: str, package_name: str) -> Any | None:
    """Import an optional library or publish a tool error."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
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
    return DnsLookup()
