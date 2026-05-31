"""Operator inventory views over shared event schemas.

Provides high-level `hosts`, `services`, and `web` commandlets so operators can
ask direct questions about the accumulated project knowledge instead of
remembering which scanner emitted which event topic.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.inventory_render import (
    host_event_keys,
    render_hosts_inventory,
    render_services_inventory,
    render_web_inventory,
    service_event_keys,
    web_event_keys,
)
from bywaf.plugins.runtime.inventory_scope import inventory_scope_label, parse_inventory_selectors, select_inventory_events

HOST_TOPICS = ("host.found", "name.resolved", "port.open", "http.endpoint", "service.detected", "finding.candidate")
SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")
WEB_TOPICS = ("http.endpoint", "http.path", "web.waf.detected", "web.screenshotted_host", "finding.candidate")


class InventoryCommand(CommandletBase):
    """Shared parser and selector behavior for inventory commandlets."""

    topics: tuple[str, ...] = ()
    identity = staticmethod(lambda event: set())

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete common inventory selectors."""
        del context, args
        candidates = ["--last", "--new", "--page", "all=true", "job=", "job=latest", "pipeline=", "step="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]

    def selected_events(self, context: CommandContext, args: list[str]) -> tuple[Namespace, list[Event], bool]:
        """Parse scope selectors and return matching events."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("--last", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parser.add_argument("selectors", nargs="*", metavar="key=value")
        parsed = parser.parse_args(args)
        selectors = parse_inventory_selectors(parsed.selectors, last=parsed.last, new=parsed.new)
        context.require_foreground(f"{self.spec.name} inventory views")
        events = select_inventory_events(context, self.topics, selectors, self.identity)
        return selectors, events, bool(parsed.page)


@commandlet(
    name="hosts",
    description="Show host inventory from accumulated scan results.",
    usage="hosts [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("hosts", "hosts --last", "hosts --new", "hosts pipeline=12", "hosts step=portscanner-...", "hosts --page"),
    consumes=HOST_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Hosts(InventoryCommand):
    """Render a compact host inventory."""

    topics = HOST_TOPICS
    identity = staticmethod(lambda event: host_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render host inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_hosts_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="services",
    description="Show service inventory by host and port.",
    usage="services [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("services", "services --last", "services --new", "services pipeline=12", "services step=portscanner-...", "services --page"),
    consumes=SERVICE_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Services(InventoryCommand):
    """Render a compact service inventory."""

    topics = SERVICE_TOPICS
    identity = staticmethod(lambda event: service_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render service inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_services_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="web",
    description="Show web endpoint inventory from accumulated scan results.",
    usage="web [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("web", "web --last", "web --new", "web pipeline=12", "web step=http-probe-...", "web --page"),
    consumes=WEB_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Web(InventoryCommand):
    """Render a compact web endpoint inventory."""

    topics = WEB_TOPICS
    identity = staticmethod(lambda event: web_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render web inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_web_inventory(context, events, inventory_scope_label(selectors))
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


def plugins() -> tuple[Commandlet, ...]:
    """Return inventory commandlets."""
    return (Hosts(), Services(), Web())
