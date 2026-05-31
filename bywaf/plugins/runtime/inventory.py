"""Operator inventory views over shared event schemas.

Provides high-level inventory commandlets so
operators can ask direct questions about the accumulated project knowledge
instead of remembering which scanner emitted which event topic.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.inventory_render import (
    banner_event_keys,
    cert_event_keys,
    host_event_keys,
    path_event_keys,
    render_hosts_inventory,
    render_banners_inventory,
    render_certs_inventory,
    render_paths_inventory,
    render_routes_inventory,
    render_screenshots_inventory,
    render_services_inventory,
    render_shares_inventory,
    render_wafs_inventory,
    render_web_inventory,
    route_event_keys,
    screenshot_event_keys,
    service_event_keys,
    share_event_keys,
    waf_event_keys,
    web_event_keys,
)
from bywaf.plugins.runtime.inventory_scope import inventory_scope_label, parse_inventory_selectors, select_inventory_events

HOST_TOPICS = ("host.found", "name.resolved", "port.open", "http.endpoint", "service.detected", "finding.candidate")
SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")
WEB_TOPICS = ("http.endpoint", "http.path", "web.waf.detected", "web.screenshotted_host", "finding.candidate")
WAF_TOPICS = ("web.waf.detected",)
SHARE_TOPICS = ("smb.share.found",)
ROUTE_TOPICS = ("network.route.hop",)
CERT_TOPICS = ("tls.certificate",)
BANNER_TOPICS = ("tcp.banner",)
PATH_TOPICS = ("http.path",)
SCREENSHOT_TOPICS = ("web.screenshotted_host",)


class InventoryCommand(CommandletBase):
    """Shared parser and selector behavior for inventory commandlets."""

    topics: tuple[str, ...] = ()
    sort_keys: tuple[str, ...] = ()
    identity = staticmethod(lambda event: set())

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete common inventory selectors."""
        del context, args
        candidates = [
            "--last",
            "--new",
            "--page",
            "all=true",
            "job=",
            "job=latest",
            "pipeline=",
            "step=",
            *(f"sort={key}" for key in self.sort_keys),
            *(f"sort=-{key}" for key in self.sort_keys),
        ]
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
        selectors = parse_inventory_selectors(
            parsed.selectors,
            last=parsed.last,
            new=parsed.new,
            sort_keys=self.sort_keys,
        )
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
    sort_keys = ("host", "name", "status", "ports", "web", "findings")
    identity = staticmethod(lambda event: host_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render host inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_hosts_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
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
    sort_keys = ("host", "port", "service", "product")
    identity = staticmethod(lambda event: service_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render service inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_services_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
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
    sort_keys = ("url", "host", "status", "server")
    identity = staticmethod(lambda event: web_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render web inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_web_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="wafs",
    description="Show WAF and edge-protection fingerprints.",
    usage="wafs [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("wafs", "wafs --last", "wafs --new", "wafs pipeline=12", "wafs step=waf-detect-...", "wafs --page"),
    consumes=WAF_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Wafs(InventoryCommand):
    """Render compact WAF fingerprint inventory."""

    topics = WAF_TOPICS
    sort_keys = ("vendor", "url", "host", "product", "confidence")
    identity = staticmethod(lambda event: waf_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render WAF inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_wafs_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="shares",
    description="Show discovered network shares.",
    usage="shares [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("shares", "shares --last", "shares --new", "shares pipeline=12", "shares step=smb-shares-...", "shares --page"),
    consumes=SHARE_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Shares(InventoryCommand):
    """Render compact network share inventory."""

    topics = SHARE_TOPICS
    sort_keys = ("host", "share", "access")
    identity = staticmethod(lambda event: share_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render share inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_shares_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="routes",
    description="Show route hops discovered by traceroute-style scans.",
    usage="routes [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("routes", "routes --last", "routes --new", "routes pipeline=12", "routes step=traceroute-...", "routes --page"),
    consumes=ROUTE_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Routes(InventoryCommand):
    """Render compact route-hop inventory."""

    topics = ROUTE_TOPICS
    sort_keys = ("target", "hop", "host", "ip", "rtt")
    identity = staticmethod(lambda event: route_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render route inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_routes_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="certs",
    description="Show TLS certificate inventory.",
    usage="certs [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("certs", "certs --last", "certs --new", "certs pipeline=12", "certs step=tls-probe-...", "certs --page"),
    consumes=CERT_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Certs(InventoryCommand):
    """Render compact TLS certificate inventory."""

    topics = CERT_TOPICS
    sort_keys = ("host", "port", "subject", "issuer", "not_after")
    identity = staticmethod(lambda event: cert_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render certificate inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_certs_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="banners",
    description="Show captured TCP banners.",
    usage="banners [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("banners", "banners --last", "banners --new", "banners pipeline=12", "banners step=tcp-banner-...", "banners --page"),
    consumes=BANNER_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Banners(InventoryCommand):
    """Render compact TCP banner inventory."""

    topics = BANNER_TOPICS
    sort_keys = ("host", "port")
    identity = staticmethod(lambda event: banner_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render banner inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_banners_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="paths",
    description="Show discovered HTTP paths.",
    usage="paths [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("paths", "paths --last", "paths --new", "paths pipeline=12", "paths step=webfin-...", "paths --page"),
    consumes=PATH_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Paths(InventoryCommand):
    """Render compact HTTP path inventory."""

    topics = PATH_TOPICS
    sort_keys = ("host", "path", "status", "url")
    identity = staticmethod(lambda event: path_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render path inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_paths_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


@commandlet(
    name="screenshots",
    description="Show screenshot artifacts by host.",
    usage="screenshots [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("screenshots", "screenshots --last", "screenshots --new", "screenshots pipeline=12", "screenshots step=screenshotter-...", "screenshots --page"),
    consumes=SCREENSHOT_TOPICS,
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Screenshots(InventoryCommand):
    """Render compact screenshot artifact inventory."""

    topics = SCREENSHOT_TOPICS
    sort_keys = ("host", "shots", "tool")
    identity = staticmethod(lambda event: screenshot_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render screenshot inventory rows."""
        del input_events
        selectors, events, page = self.selected_events(context, args)
        output = render_screenshots_inventory(context, events, inventory_scope_label(selectors), selectors.sort)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()


def plugins() -> tuple[Commandlet, ...]:
    """Return inventory commandlets."""
    return (Hosts(), Services(), Web(), Wafs(), Shares(), Routes(), Certs(), Banners(), Paths(), Screenshots())
