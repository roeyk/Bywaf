"""Inventory aggregation and rendering modules.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from .facts import (
    banner_event_keys,
    cert_event_keys,
    path_event_keys,
    render_banners_inventory,
    render_certs_inventory,
    render_paths_inventory,
    render_routes_inventory,
    render_screenshots_inventory,
    render_shares_inventory,
    route_event_keys,
    screenshot_event_keys,
    share_event_keys,
)
from .hosts import host_event_keys, render_hosts_inventory
from .services import service_event_keys, render_services_inventory
from .web import render_wafs_inventory, render_web_inventory, waf_event_keys, web_event_keys

__all__ = [
    "banner_event_keys",
    "cert_event_keys",
    "host_event_keys",
    "path_event_keys",
    "render_banners_inventory",
    "render_certs_inventory",
    "render_hosts_inventory",
    "render_paths_inventory",
    "render_routes_inventory",
    "render_screenshots_inventory",
    "render_services_inventory",
    "render_shares_inventory",
    "render_wafs_inventory",
    "render_web_inventory",
    "route_event_keys",
    "screenshot_event_keys",
    "service_event_keys",
    "share_event_keys",
    "waf_event_keys",
    "web_event_keys",
]
