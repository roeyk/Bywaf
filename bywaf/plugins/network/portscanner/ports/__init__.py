"""Open-port result view for the portscanner provider.

Provides a pentester-oriented view over `port.open` events.  The raw event log
remains available for audit work, while this command answers the common
operator question: "what did the latest port scan find?"

Used by:
- network.portscanner provider: exposes the companion `ports` view commandlet.
- REPL operators: inspect latest or selected portscanner results."""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable

from bywaf.event.filters import filter_events_by_payload
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.runtime_display import (
    runtime_sort_completion_candidates,
    runtime_sort_key,
    runtime_sort_note,
)

from .events import latest_portscanner_scope, select_port_events
from .render import (
    ip_sort_value as ip_sort_value,
    port_endpoint_text as port_endpoint_text,
    render_ports_table,
    sort_port_events as sort_port_events,
)
from .selectors import PORT_SORT_KEYS, parse_ports_selectors


@commandlet(
    name="ports",
    description="Show open ports from the latest or selected port scan.",
    usage="ports [--last|--new] [job=latest|<id>] [pipeline=<id>] [step=<id>] [host=<selector>] [port=<selector>] [sort=<key>] [all=true]",
    examples=(
        "ports",
        "ports --last",
        "ports --new",
        "ports job=latest",
        "ports job=69 sort=host",
        "ports host=192.168.50.0/24,!192.168.50.1-128 port=80,443",
    ),
)
class Ports(CommandletBase):
    """Render a compact table of open-port discoveries."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse selectors, select port events, and print a result table."""
        del input_events
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("--last", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        selectors = parse_ports_selectors(tokens, last=parsed.last, new=parsed.new)
        context.require_foreground("port result views")
        events = select_port_events(context, selectors)
        events = filter_events_by_payload(events, selectors.filters)
        if not events:
            context.output(no_ports_message(selectors))
            return ()
        output = render_ports(context, events, selectors)
        if parsed.page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete selectors and sort keys."""
        del context
        candidates = [
            "--page",
            "--last",
            "--new",
            "all=true",
            "job=",
            "job=latest",
            "pipeline=",
            "step=",
            "host=",
            "port=",
            "protocol=",
            "service=",
            "reason=",
            "sort=",
        ]
        if args and args[-1].startswith("sort="):
            return runtime_sort_completion_candidates(args[-1], PORT_SORT_KEYS)
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def render_ports(context: CommandContext, events: list[Event], selectors: Namespace) -> str:
    """Render the selected open ports as a compact table."""
    scope = ports_scope_label(context, selectors)
    table = render_ports_table(context, events, selectors.sort)
    heading = f"Ports: {scope} ({len(events)} open port{'s' if len(events) != 1 else ''})"
    if runtime_sort_key(selectors.sort) in {"host", "port"}:
        return f"{heading}\n{runtime_sort_note(selectors.sort, label='grouped by')}\n{table}"
    return f"{heading}\n{runtime_sort_note(selectors.sort)}\n{table}"


def ports_scope_label(context: CommandContext, selectors: Namespace) -> str:
    """Return a short human-readable scope description."""
    scope = selectors.scope
    if getattr(selectors, "new", False):
        prefix = "new in "
    elif getattr(selectors, "last", False):
        prefix = "latest "
    else:
        prefix = ""
    if scope.get("all") == "true":
        return "all port.open events"
    if scope.get("job") == "latest" or (not scope and not getattr(selectors, "new", False)):
        latest = latest_portscanner_scope(context)
        if latest is not None and latest.job_id:
            return f"latest portscanner job={latest.job_id}"
        return "latest portscanner scan"
    if getattr(selectors, "new", False) and not scope:
        return "new since prior port inventory"
    if "job" in scope:
        return f"{prefix}job={scope['job']}"
    if "pipeline" in scope:
        return f"{prefix}pipeline={scope['pipeline']}"
    if "step" in scope:
        return f"{prefix}step={scope['step']}"
    return "selected port.open events"


def no_ports_message(selectors: Namespace) -> str:
    """Return the empty-result message for the selected scope."""
    if selectors.scope:
        return "no port.open events for selected scope"
    return "no port scan results"


def plugin() -> Commandlet:
    """Return the runtime ports commandlet."""
    return Ports()


__all__ = [
    "PORT_SORT_KEYS",
    "Ports",
    "ip_sort_value",
    "plugin",
    "port_endpoint_text",
    "render_ports",
    "sort_port_events",
]
