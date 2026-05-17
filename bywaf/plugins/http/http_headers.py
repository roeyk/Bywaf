"""HTTP header fetcher compatible with the original example plugin."""

from __future__ import annotations

import http.client
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option

DEFAULTS = {"port": "", "ssl": "false", "target": "", "timeout": 5}


@commandlet(
    name="http_headers",
    description="Fetch HTTP response headers for a target.",
    usage="http_headers [options] [target]",
    examples=(
        "http_headers --ssl true example.test",
        "hostscanner 127.0.0.1 | portscanner --ports 80,443 | http_headers",
    ),
    consumes=("port.open",),
    emits=("http.headers",),
    capabilities=("network.connect",),
)
@option("port", "target port")
@option("ssl", "use HTTPS", "false", ("true", "false"))
@option("timeout", "connection timeout", "5")
class HttpHeaders(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Fetch HEAD response metadata for explicit or pipeline targets."""
        parser = self.parser()
        parser.add_argument("target", nargs="?")
        parser.add_argument("--port", type=int, default=self.var_default(context, "port", None, cast=int))
        parser.add_argument("--ssl", choices=("true", "false"), default=self.var_default(context, "ssl", "false"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parsed = parser.parse_args(args)
        target = parsed.target or self.var_default(context, "target", None)
        targets = self.targets(target, parsed.port, parsed.ssl == "true", input_events)
        for host, port, use_ssl in targets:
            context.audit_capability("network.connect")
            connection_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
            conn = connection_cls(host, port=port, timeout=parsed.timeout)
            try:
                conn.request("HEAD", "/")
                response = conn.getresponse()
                yield {"host": host, "port": port, "status": response.status, "headers": dict(response.headers)}
            finally:
                conn.close()

    def targets(self, target, port, use_ssl, input_events):
        """Resolve an explicit target or derive targets from `port.open` events."""
        if target:
            return [(target, port or (443 if use_ssl else 80), use_ssl)]
        return [
            (event.payload["host"], int(event.payload["port"]), int(event.payload["port"]) == 443)
            for event in input_events
            if "host" in event.payload and "port" in event.payload
        ]


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HttpHeaders()
