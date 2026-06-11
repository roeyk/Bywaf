"""HTTP method inspection commandlet.

Provides a bundled plugin provider facade for HTTP OPTIONS method probing.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute the `http_methods` commandlet through normal
  dispatch.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.targets import (
    build_url as build_url,
    choose_scheme as choose_scheme,
    normalize_path as normalize_path,
    split_host_port as split_host_port,
)

from .command import DEFAULTS, MethodTarget, method_targets, run_http_methods, target_from_port_event, target_from_text
from .detect import http, normalize_methods, probe_methods
from .findings import WEBDAV_METHODS, WRITE_METHODS, method_findings, methods_from_payload, result_payload, target_payload

# Stable package facade for the HTTP methods plugin. The split modules keep
# orchestration, probing, and finding mapping testable in isolation while this
# package remains the provider entry point and compatibility import surface.
__all__ = [
    "DEFAULTS",
    "HttpMethods",
    "MethodTarget",
    "WEBDAV_METHODS",
    "WRITE_METHODS",
    "build_url",
    "choose_scheme",
    "http",
    "method_findings",
    "method_targets",
    "methods_from_payload",
    "normalize_methods",
    "normalize_path",
    "plugin",
    "probe_methods",
    "result_payload",
    "run_http_methods",
    "split_host_port",
    "target_from_port_event",
    "target_from_text",
    "target_payload",
]


@commandlet(
    name="http_methods",
    description="Probe HTTP OPTIONS and report risky allowed methods.",
    usage="http_methods [options] [target ...]",
    examples=(
        "http_methods https://example.test/",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_methods",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("silent", "suppress probe alerts", "false")
@option("timeout", "request timeout seconds", "5")
class HttpMethods(CommandletBase):
    """Probe OPTIONS and emit method posture facts plus candidates.

    Called by: PluginRegistry/runner dispatch for the `http_methods`
    commandlet.

    Delegates to: `run_http_methods()` for parsing, target resolution,
    probing, event payload creation, and finding promotion.
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
        yield from run_http_methods(self, context, args, input_events)

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `MethodTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in method_targets(list(targets or []), input_events, scheme, path)
        ]


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpMethods()
