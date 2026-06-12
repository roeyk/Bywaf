"""Facade for inventory view renderers.

Used by: `runtime.inventory` commandlet classes so the provider facade can
import one compact renderer surface instead of each view module individually.
"""

from __future__ import annotations

from .views.banners import banner_event_keys, render_banners_inventory
from .views.certs import cert_event_keys, render_certs_inventory
from .views.hosts import host_event_keys, render_hosts_inventory
from .views.paths import path_event_keys, render_paths_inventory
from .views.routes import render_routes_inventory, route_event_keys
from .views.screenshots import render_screenshots_inventory, screenshot_event_keys
from .views.services import service_event_keys, render_services_inventory
from .views.shares import render_shares_inventory, share_event_keys
from .views.web import render_wafs_inventory, render_web_inventory, waf_event_keys, web_event_keys

# Stable inventory rendering facade exports. Concrete inventory commandlets use
# this surface so individual view modules can stay focused by topic.
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
