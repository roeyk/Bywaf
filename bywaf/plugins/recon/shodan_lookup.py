"""Shodan lookup commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Queries Shodan-style data sources and emits external recon events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import os
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugin import kv_to_args
from bywaf.plugins.recon.dns_lookup import optional_module

DEFAULTS = {"api-key": "", "limit": "10", "mode": "host"}
OPTION_KEYS = {"api-key", "limit", "mode"}


@commandlet(
    name="shodan_lookup",
    description="Query Shodan host or search data.",
    usage="shodan_lookup [mode=host|search] [api-key=KEY] <ip-or-query>",
    examples=("shodan_lookup 8.8.8.8", "shodan_lookup mode=search apache country:US"),
)
@option("api-key", "Shodan API key; defaults to SHODAN_API_KEY", secret=True)
@option("limit", "maximum search results", "10")
@option("mode", "lookup mode", "host", ("host", "search"))
class ShodanLookup(CommandletBase):
    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Run a Shodan host lookup or search query."""
        del input_events
        parser = self.parser()
        parser.add_argument("query", nargs="+")
        parser.add_argument("--api-key", default=self.var_default(context, "api-key", ""))
        parser.add_argument("--limit", type=int, default=self.var_default(context, "limit", 10, cast=int))
        parser.add_argument("--mode", choices=("host", "search"), default=self.var_default(context, "mode", "host"))
        parsed = parser.parse_args(kv_to_args(args, OPTION_KEYS))
        shodan_mod = optional_module(context, "shodan", "shodan")
        if shodan_mod is None:
            return ()
        api_key = context.secrets.resolve(parsed.api_key, "") or os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            # Shodan needs credentials, but missing credentials are an
            # operational error rather than a command parser failure.
            context.events.publish("tool.error", {"tool": "shodan", "severity": "error", "message": "missing Shodan API key"})
            return ()
        api = shodan_mod.Shodan(api_key)
        context.audit_capability("network.connect")
        if parsed.mode == "host":
            for host in parsed.query:
                # Host mode preserves Shodan's host payload because the API
                # already returns a structured document.
                try:
                    context.events.publish("shodan.host", api.host(host))
                except Exception as exc:
                    publish_shodan_error(context, f"host lookup failed for {host}: {exc}")
        else:
            query = " ".join(parsed.query)
            try:
                result = api.search(query, limit=parsed.limit)
            except Exception as exc:
                publish_shodan_error(context, f"search failed for {query}: {exc}")
                return ()
            for match in result.get("matches", []):
                context.events.publish("shodan.result", match)
        return ()


def publish_shodan_error(context: CommandContext, message: str) -> None:
    """Publish one operational Shodan failure."""
    context.events.publish("tool.error", {"tool": "shodan", "severity": "error", "message": message})


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return ShodanLookup()
