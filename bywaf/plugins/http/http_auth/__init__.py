"""HTTP authentication challenge posture commandlet.

Provides a bundled plugin provider facade for HTTP authentication posture
probing.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute the `http_auth` commandlet through normal dispatch.
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

from .command import DEFAULTS, AuthTarget, auth_targets, run_http_auth, target_from_port_event, target_from_text
from .detect import challenge_realms, http, normalize_schemes, probe_auth
from .findings import (
    ADMIN_PATH_HINTS,
    auth_findings,
    is_adminish_path,
    realms_from_payload,
    result_payload,
    schemes_from_payload,
    target_payload,
)

# Stable package facade for the HTTP auth plugin. The split modules keep
# orchestration, probing, and finding mapping testable in isolation while this
# package remains the provider entry point and compatibility import surface.
__all__ = [
    "ADMIN_PATH_HINTS",
    "AuthTarget",
    "DEFAULTS",
    "HttpAuth",
    "auth_findings",
    "auth_targets",
    "build_url",
    "challenge_realms",
    "choose_scheme",
    "http",
    "is_adminish_path",
    "normalize_path",
    "normalize_schemes",
    "plugin",
    "probe_auth",
    "realms_from_payload",
    "result_payload",
    "run_http_auth",
    "schemes_from_payload",
    "split_host_port",
    "target_from_port_event",
    "target_from_text",
    "target_payload",
]


@commandlet(
    name="http_auth",
    description="Probe HTTP auth challenges and report passive auth posture findings.",
    usage="http_auth [options] [target ...]",
    examples=(
        "http_auth https://example.test/admin",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_auth path=/admin",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("method", "HTTP method", "HEAD", ("HEAD", "GET"))
@option("timeout", "request timeout seconds", "5")
class HttpAuth(CommandletBase):
    """Probe one request and emit HTTP authentication posture facts.

    Called by: PluginRegistry/runner dispatch for the `http_auth` commandlet.

    Delegates to: `run_http_auth()` for parsing, target resolution, probing,
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
        yield from run_http_auth(self, context, args, input_events)

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `AuthTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in auth_targets(list(targets or []), input_events, scheme, path)
        ]


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpAuth()
