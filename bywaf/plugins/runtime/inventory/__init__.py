"""Operator inventory views over shared event schemas.

Provides high-level inventory commandlets so
operators can ask direct questions about the accumulated project knowledge
instead of remembering which scanner emitted which event topic.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, commandlet
from bywaf.plugins.runtime.inventory.command import InventoryCommand
from bywaf.plugins.runtime.inventory.render import (
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
from bywaf.plugins.runtime.inventory.topics import (
    BANNER_TOPICS,
    CERT_TOPICS,
    HOST_TOPICS,
    PATH_TOPICS,
    ROUTE_TOPICS,
    SCREENSHOT_TOPICS,
    SERVICE_TOPICS,
    SHARE_TOPICS,
    WAF_TOPICS,
    WEB_TOPICS,
)


@commandlet(
    name="hosts",
    description="Show host inventory from accumulated scan results.",
    usage="hosts [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("hosts", "hosts --last", "hosts --new", "hosts pipeline=12", "hosts step=portscanner-...", "hosts --page"),
)
class Hosts(InventoryCommand):
    """Render a compact host inventory."""

    topics = HOST_TOPICS
    sort_keys = ("host", "name", "status", "ports", "web", "findings")
    identity = staticmethod(lambda event: host_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render host inventory rows."""
        return self.render_inventory(context, args, input_events, render_hosts_inventory)


@commandlet(
    name="services",
    description="Show service inventory by host and port.",
    usage="services [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("services", "services --last", "services --new", "services pipeline=12", "services step=portscanner-...", "services --page"),
)
class Services(InventoryCommand):
    """Render a compact service inventory."""

    topics = SERVICE_TOPICS
    sort_keys = ("host", "port", "service", "product")
    identity = staticmethod(lambda event: service_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render service inventory rows."""
        return self.render_inventory(context, args, input_events, render_services_inventory)


@commandlet(
    name="web",
    description="Show web endpoint inventory from accumulated scan results.",
    usage="web [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("web", "web --last", "web --new", "web pipeline=12", "web step=http-probe-...", "web --page"),
)
class Web(InventoryCommand):
    """Render a compact web endpoint inventory."""

    topics = WEB_TOPICS
    sort_keys = ("url", "host", "status", "server", "tech")
    identity = staticmethod(lambda event: web_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render web inventory rows."""
        return self.render_inventory(context, args, input_events, render_web_inventory)


@commandlet(
    name="wafs",
    description="Show WAF and edge-protection fingerprints.",
    usage="wafs [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("wafs", "wafs --last", "wafs --new", "wafs pipeline=12", "wafs step=waf-detect-...", "wafs --page"),
)
class Wafs(InventoryCommand):
    """Render compact WAF fingerprint inventory."""

    topics = WAF_TOPICS
    sort_keys = ("vendor", "url", "host", "product", "confidence")
    identity = staticmethod(lambda event: waf_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render WAF inventory rows."""
        return self.render_inventory(context, args, input_events, render_wafs_inventory)


@commandlet(
    name="shares",
    description="Show discovered network shares.",
    usage="shares [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("shares", "shares --last", "shares --new", "shares pipeline=12", "shares step=smb-shares-...", "shares --page"),
)
class Shares(InventoryCommand):
    """Render compact network share inventory."""

    topics = SHARE_TOPICS
    sort_keys = ("host", "share", "access")
    identity = staticmethod(lambda event: share_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render share inventory rows."""
        return self.render_inventory(context, args, input_events, render_shares_inventory)


@commandlet(
    name="routes",
    description="Show route hops discovered by traceroute-style scans.",
    usage="routes [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("routes", "routes --last", "routes --new", "routes pipeline=12", "routes step=traceroute-...", "routes --page"),
)
class Routes(InventoryCommand):
    """Render compact route-hop inventory."""

    topics = ROUTE_TOPICS
    sort_keys = ("target", "hop", "host", "ip", "rtt")
    identity = staticmethod(lambda event: route_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render route inventory rows."""
        return self.render_inventory(context, args, input_events, render_routes_inventory)


@commandlet(
    name="certs",
    description="Show TLS certificate inventory.",
    usage="certs [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("certs", "certs --last", "certs --new", "certs pipeline=12", "certs step=tls-probe-...", "certs --page"),
)
class Certs(InventoryCommand):
    """Render compact TLS certificate inventory."""

    topics = CERT_TOPICS
    sort_keys = ("host", "port", "subject", "issuer", "not_after")
    identity = staticmethod(lambda event: cert_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render certificate inventory rows."""
        return self.render_inventory(context, args, input_events, render_certs_inventory)


@commandlet(
    name="banners",
    description="Show captured TCP banners.",
    usage="banners [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("banners", "banners --last", "banners --new", "banners pipeline=12", "banners step=tcp-banner-...", "banners --page"),
)
class Banners(InventoryCommand):
    """Render compact TCP banner inventory."""

    topics = BANNER_TOPICS
    sort_keys = ("host", "port")
    identity = staticmethod(lambda event: banner_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render banner inventory rows."""
        return self.render_inventory(context, args, input_events, render_banners_inventory)


@commandlet(
    name="paths",
    description="Show discovered HTTP paths.",
    usage="paths [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("paths", "paths --last", "paths --new", "paths pipeline=12", "paths step=webfin-...", "paths --page"),
)
class Paths(InventoryCommand):
    """Render compact HTTP path inventory."""

    topics = PATH_TOPICS
    sort_keys = ("host", "path", "status", "url")
    identity = staticmethod(lambda event: path_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render path inventory rows."""
        return self.render_inventory(context, args, input_events, render_paths_inventory)


@commandlet(
    name="screenshots",
    description="Show screenshot artifacts by host.",
    usage="screenshots [--last|--new] [job=<id>|pipeline=<id>|step=<id>|all=true] [--page]",
    examples=("screenshots", "screenshots --last", "screenshots --new", "screenshots pipeline=12", "screenshots step=screenshotter-...", "screenshots --page"),
)
class Screenshots(InventoryCommand):
    """Render compact screenshot artifact inventory."""

    topics = SCREENSHOT_TOPICS
    sort_keys = ("host", "shots", "tool")
    identity = staticmethod(lambda event: screenshot_event_keys(event))

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render screenshot inventory rows."""
        return self.render_inventory(context, args, input_events, render_screenshots_inventory)


def plugins() -> tuple[Commandlet, ...]:
    """Return inventory commandlets."""
    return (Hosts(), Services(), Web(), Wafs(), Shares(), Routes(), Certs(), Banners(), Paths(), Screenshots())
