"""Compatibility facade for single-topic inventory renderers."""

from __future__ import annotations

from .banners import banner_event_keys, render_banners_inventory
from .certs import cert_event_keys, render_certs_inventory
from .paths import path_event_keys, render_paths_inventory
from .routes import render_routes_inventory, route_event_keys
from .screenshots import render_screenshots_inventory, screenshot_event_keys
from .shares import render_shares_inventory, share_event_keys

__all__ = [
    "banner_event_keys",
    "cert_event_keys",
    "path_event_keys",
    "render_banners_inventory",
    "render_certs_inventory",
    "render_paths_inventory",
    "render_routes_inventory",
    "render_screenshots_inventory",
    "render_shares_inventory",
    "route_event_keys",
    "screenshot_event_keys",
    "share_event_keys",
]
