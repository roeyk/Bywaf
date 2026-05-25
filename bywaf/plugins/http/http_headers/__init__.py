"""HTTP header inspection commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Fetches response headers and emits HTTP observation events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option

from .command import header_targets, run_http_headers
from .detect import fetch_headers
from .findings import missing_security_header_candidates, result_payload
from .models import HeaderProbeResult, HeaderTarget

# Public compatibility surface for older imports and tests. The implementation
# now lives in split files, but the provider package remains the stable import
# point for PluginRegistry and callers.
__all__ = [
    "DEFAULTS",
    "HeaderProbeResult",
    "HeaderTarget",
    "HttpHeaders",
    "fetch_headers",
    "missing_security_header_candidates",
    "plugin",
    "result_payload",
    "run_http_headers",
]

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
    emits=("http.headers", "finding.candidate"),
    capabilities=("db.write:finding.candidate", "network.connect"),
)
@option("port", "target port")
@option("ssl", "use HTTPS", "false", ("true", "false"))
@option("timeout", "connection timeout", "5")
class HttpHeaders(CommandletBase):
    """Thin commandlet wrapper around split HTTP header check modules."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Fetch HEAD response metadata for explicit or pipeline targets."""
        yield from run_http_headers(self, context, args, input_events)

    def targets(self, target, port, use_ssl, input_events):
        """Resolve an explicit target or derive targets from `port.open` events."""
        return [
            (header_target.host, header_target.port, header_target.use_ssl)
            for header_target in header_targets(target, port, use_ssl, input_events)
        ]


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HttpHeaders()
