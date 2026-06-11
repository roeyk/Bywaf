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

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase
from bywaf.plugins.target_policy import filter_targets_by_host

from .detect import fetch_headers
from .findings import missing_sec_headers, result_payload
from .models import HeaderTarget


def run_http_headers(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Fetch HEAD response metadata for explicit or pipeline targets.

    Called by: `HttpHeaders.run()`.

    Emits yielded `http.headers` payloads plus persisted
    `finding.candidate` events.
    """
    parser = commandlet.parser()
    # Decorators expose option metadata; argparse below is still the execution
    # parser. Keep both in sync when adding plugin variables.
    # Add the optional positional host/URL argument to the runtime parser.
    parser.add_argument("target", nargs="?")
    # Read each option from CLI args, falling back to commandlet variables when
    # an operator has configured defaults with `vars`.
    parser.add_argument("--port", type=int, default=commandlet.var_default(context, "port", None, cast=int))
    parser.add_argument("--ssl", choices=("true", "false"), default=commandlet.var_default(context, "ssl", "false"))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", 5, cast=float))
    # Parse commandlet arguments into an argparse namespace.
    parsed = parser.parse_args(args)
    # Prefer the command-line target, then fall back to a configured target var.
    target = parsed.target or commandlet.var_default(context, "target", None)

    # Resolve explicit or upstream targets, then apply the global target-scope
    # policy by comparing each `HeaderTarget` by host.
    targets = filter_targets_by_host(
        context,
        header_targets(target, parsed.port, parsed.ssl == "true", input_events),
        lambda header_target: header_target.host,
    )
    for header_target in targets:
        # Record actual runtime use of the declared network capability.
        context.audit_capability("network.connect")

        # Detection returns a neutral fact. Finding packaging is a separate
        # step so tests can exercise probe logic without Bywaf runtime context.
        # Open the connection and collect one target's HEAD response headers.
        result = fetch_headers(header_target, timeout=parsed.timeout)

        # Convert the domain result into the plugin-owned `http.headers`
        # payload shape that the framework will persist for yielded outputs.
        payload = result_payload(result)

        # Promote reportable missing/weak header observations to durable
        # finding candidates before yielding the raw header fact.
        for candidate in missing_sec_headers(result):
            context.events.publish("finding.candidate", candidate)
        yield payload


def header_targets(target, port, use_ssl, input_events: Iterable[Event]) -> list[HeaderTarget]:
    """Resolve an explicit target or derive targets from `port.open` events.

    Called by: `run_http_headers()` and compatibility `HttpHeaders.targets()`.
    """
    if target:
        # Build a single direct target. If the caller omitted the port, derive
        # the conventional default from the chosen scheme.
        return [HeaderTarget(str(target), int(port or (443 if use_ssl else 80)), bool(use_ssl))]

    # Pipeline mode: convert upstream port events into header probe targets.
    # Port 443 implies HTTPS unless an explicit target was provided above.
    return [
        HeaderTarget(str(event.payload["host"]), int(event.payload["port"]), int(event.payload["port"]) == 443)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]
