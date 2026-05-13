"""HTTP header fetcher compatible with the original example plugin."""

from __future__ import annotations

import http.client
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CommandSpec, OptionSpec

DEFAULTS = {"ssl": "false", "timeout": 5}


class HttpHeaders(CommandletBase):
    spec = CommandSpec(
        name="http_headers",
        description="Fetch HTTP response headers for a target.",
        usage="http_headers [options] [target]",
        examples=(
            "http_headers --ssl true example.test",
            "hostscanner 127.0.0.1 | portscanner --ports 80,443 | http_headers",
        ),
        options=(
            OptionSpec("port", "target port"),
            OptionSpec("ssl", "use HTTPS", "false", ("true", "false")),
            OptionSpec("timeout", "connection timeout", "5"),
        ),
        consumes=("port.open",),
        emits=("http.headers",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Fetch HEAD response metadata for explicit or pipeline targets."""
        parser = self.parser()
        parser.add_argument("target", nargs="?")
        parser.add_argument("--port", type=int)
        parser.add_argument("--ssl", choices=("true", "false"), default="false")
        parser.add_argument("--timeout", type=float, default=5)
        parsed = parser.parse_args(args)
        targets = self.targets(parsed.target, parsed.port, parsed.ssl == "true", input_events)
        for host, port, use_ssl in targets:
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
