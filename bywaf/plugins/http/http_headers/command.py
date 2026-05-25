"""Command orchestration for HTTP header checks.

Provides argument parsing, target selection, console output, event publishing,
and finding publication for the `http_headers` commandlet.

Consumes:
- `port.open` events or explicit host command arguments.

Emits:
- `http.headers` for observed HTTP response headers.
- `finding.candidate` for missing high-value security headers.

Used by:
- HTTP header plugin registration: delegate commandlet execution.
- tests: exercise Bywaf integration separately from pure detection logic."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, CommandletBase

from .detect import fetch_headers
from .findings import missing_security_header_candidates, result_payload
from .models import HeaderTarget


def run_http_headers(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Fetch HEAD response metadata for explicit or pipeline targets."""
    parser = commandlet.parser()
    # Decorators expose option metadata; argparse below is still the execution
    # parser. Keep both in sync when adding plugin variables.
    parser.add_argument("target", nargs="?")
    parser.add_argument("--port", type=int, default=commandlet.var_default(context, "port", None, cast=int))
    parser.add_argument("--ssl", choices=("true", "false"), default=commandlet.var_default(context, "ssl", "false"))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", 5, cast=float))
    parsed = parser.parse_args(args)
    target = parsed.target or commandlet.var_default(context, "target", None)
    targets = header_targets(target, parsed.port, parsed.ssl == "true", input_events)
    for header_target in targets:
        # Detection returns a neutral fact. Finding packaging is a separate
        # step so tests can exercise probe logic without Bywaf runtime context.
        context.audit_capability("network.connect")
        result = fetch_headers(header_target, timeout=parsed.timeout)
        payload = result_payload(result)
        for candidate in missing_security_header_candidates(result):
            context.events.publish("finding.candidate", candidate)
        yield payload


def header_targets(target, port, use_ssl, input_events: Iterable[Event]) -> list[HeaderTarget]:
    """Resolve an explicit target or derive targets from `port.open` events."""
    if target:
        return [HeaderTarget(str(target), int(port or (443 if use_ssl else 80)), bool(use_ssl))]
    return [
        HeaderTarget(str(event.payload["host"]), int(event.payload["port"]), int(event.payload["port"]) == 443)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]
