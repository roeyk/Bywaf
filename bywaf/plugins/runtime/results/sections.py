"""Domain-specific result sections for the results command.

Compatibility facade for result-section renderers split by domain.
"""

from __future__ import annotations

from .http_sections import (
    header_count,
    missing_header_summary,
    observation_summary,
    render_http_endpoints_section,
    render_http_headers_section,
    render_http_paths_section,
    render_waf_section,
    render_web_fingerprints_section,
)
from .network_sections import (
    equivalent_ports_command,
    format_rtt,
    render_hosts_section,
    render_name_resolution_section,
    render_ports_section,
    render_route_hops_section,
    render_screenshots_section,
    render_services_section,
    render_tcp_banners_section,
    render_tls_certificates_section,
    screenshot_artifact_refs,
)
from .share_sections import format_bool, render_smb_shares_section

__all__ = [
    "equivalent_ports_command",
    "format_bool",
    "format_rtt",
    "header_count",
    "missing_header_summary",
    "observation_summary",
    "render_hosts_section",
    "render_http_endpoints_section",
    "render_http_headers_section",
    "render_http_paths_section",
    "render_name_resolution_section",
    "render_ports_section",
    "render_route_hops_section",
    "render_screenshots_section",
    "render_services_section",
    "render_smb_shares_section",
    "render_tcp_banners_section",
    "render_tls_certificates_section",
    "render_waf_section",
    "render_web_fingerprints_section",
    "screenshot_artifact_refs",
]
