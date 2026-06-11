"""HTTP CORS posture commandlet.

Provides a bundled plugin provider facade for CORS posture probing.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute the `http_cors` commandlet through normal dispatch.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.http_targets import (
    build_url as build_url,
    choose_scheme as choose_scheme,
    normalize_path as normalize_path,
    split_host_port as split_host_port,
)

from .command import DEFAULTS, CorsTarget, cors_targets, run_http_cors, target_from_port_event, target_from_text
from .detect import http, probe_cors, same_origin_value, truthy_header
from .findings import cors_finding, cors_findings, result_payload, target_payload

# Stable package facade for the CORS posture plugin. The split modules keep
# orchestration, probing, and finding mapping testable in isolation while this
# package remains the provider entry point and compatibility import surface.
__all__ = [
    "DEFAULTS",
    "CorsTarget",
    "HttpCors",
    "build_url",
    "choose_scheme",
    "cors_finding",
    "cors_findings",
    "cors_targets",
    "http",
    "normalize_path",
    "plugin",
    "probe_cors",
    "result_payload",
    "same_origin_value",
    "split_host_port",
    "target_from_port_event",
    "target_from_text",
    "target_payload",
    "truthy_header",
]


@commandlet(
    name="http_cors",
    description="Probe HTTP CORS posture and report unsafe cross-origin policy candidates.",
    usage="http_cors [options] [target ...]",
    examples=(
        "http_cors https://example.test/api",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_cors path=/api",
    ),
)
@option("origin", "Origin header value", DEFAULTS["origin"])
@option("path", "request path", DEFAULTS["path"])
@option("request-method", "CORS requested method", DEFAULTS["request_method"], ("GET", "POST", "PUT", "DELETE", "PATCH"))
@option("scheme", "scheme override", DEFAULTS["scheme"], ("auto", "http", "https"))
@option("timeout", "request timeout seconds", "5")
class HttpCors(CommandletBase):
    """Commandlet wrapper around split HTTP CORS modules.

    Called by: PluginRegistry/runner dispatch for the `http_cors` commandlet.

    Delegates to: `run_http_cors()` for parsing, target resolution, probing,
    event payload creation, and finding promotion.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        # Delegate execution to command.py so this provider module stays as the
        # stable registry/import surface rather than owning orchestration logic.
        yield from run_http_cors(self, context, args, input_events)

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `CorsTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in cors_targets(list(targets or []), input_events, scheme, path)
        ]


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpCors()
