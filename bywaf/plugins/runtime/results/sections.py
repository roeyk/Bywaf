"""Domain-specific result sections for the results command."""

from __future__ import annotations

from argparse import Namespace
from collections import Counter

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.network.portscanner.ports import render_ports
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width
from bywaf.style import styled_subject_text


def render_hosts_section(context: CommandContext, events: list[Event]) -> str:
    """Render discovered hosts as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("name", ""),
            event.payload.get("status", ""),
            event.payload.get("scanner", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "NAME", "STATUS", "SCANNER"),
        rows,
        cell_subjects=("host", "host.name", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Hosts discovered ({len(events)})\n{table}"


def render_name_resolution_section(context: CommandContext, events: list[Event]) -> str:
    """Render name-to-address mappings as one row per original name."""
    # First group host facts by submitted name, then render one de-duplicated
    # address list per name so repeated resolver observations stay readable.
    grouped: dict[str, list[str]] = {}
    for event in events:
        name = str(event.payload.get("name") or "")
        host = event.payload.get("host")
        if host is None:
            continue
        grouped.setdefault(name, []).append(str(host))
    rows = [(name, ", ".join(dict.fromkeys(sorted(hosts)))) for name, hosts in sorted(grouped.items())]
    table = render_table(
        ("NAME", "RESOLVED HOSTS"),
        rows,
        cell_subjects=("host.name", "host"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Name resolutions ({len(events)})\n{table}"


def render_ports_section(context: CommandContext, events: list[Event], scope: Namespace) -> str:
    """Render delegated open-port results with the equivalent view command."""
    command = equivalent_ports_command(scope)
    command = styled_subject_text(command_context_style_getter(context), "command_line", command)
    table = render_ports(context, events, Namespace(scope=scope.scope, filters={}, sort=scope.sort))
    return f"Output of: ports\nEquivalent command: {command}\n\n{table}"


def equivalent_ports_command(scope: Namespace) -> str:
    """Return the `ports` command that would render the same result section."""
    args = [f"{key}={value}" for key, value in scope.scope.items()]
    args.append(f"sort={scope.sort}")
    if args:
        return "ports " + " ".join(args)
    return "ports"


def render_http_endpoints_section(context: CommandContext, events: list[Event]) -> str:
    """Render reachable HTTP endpoints as a compact result table."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("server", ""),
            event.payload.get("error", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "SERVER", "ERROR"),
        rows,
        cell_subjects=("url", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP endpoints ({len(events)})\n{table}"


def render_http_headers_section(context: CommandContext, events: list[Event]) -> str:
    """Render HTTP header probe results."""
    # Header events can carry large dictionaries; this section reduces them to
    # count plus high-value missing-header summary before table rendering.
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("status", ""),
            header_count(event.payload.get("headers")),
            missing_header_summary(event.payload.get("headers")),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "STATUS", "HEADERS", "MISSING"),
        rows,
        cell_subjects=("host", "port", "status", "value", "finding.title"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP headers ({len(events)})\n{table}"


def header_count(value: object) -> int | str:
    """Return the number of observed headers."""
    return len(value) if isinstance(value, dict) else ""


def missing_header_summary(value: object) -> str:
    """Return missing high-value headers from an observed header mapping."""
    if not isinstance(value, dict):
        return ""
    observed = {str(header).lower() for header in value}
    expected = ("strict-transport-security", "x-content-type-options")
    missing = [header for header in expected if header not in observed]
    return ", ".join(missing)


def render_tcp_banners_section(context: CommandContext, events: list[Event]) -> str:
    """Render TCP banner probe results as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("banner", "") or event.payload.get("error", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "BANNER / ERROR"),
        rows,
        cell_subjects=("host", "port", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TCP banners ({len(events)})\n{table}"


def render_services_section(context: CommandContext, events: list[Event]) -> str:
    """Render normalized service classifications."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("protocol", ""),
            event.payload.get("service", ""),
            event.payload.get("product", "") or event.payload.get("evidence", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "EVIDENCE"),
        rows,
        cell_subjects=("host", "port", "protocol", "value", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Services detected ({len(events)})\n{table}"


def render_tls_certificates_section(context: CommandContext, events: list[Event]) -> str:
    """Render TLS certificate metadata."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("subject", ""),
            event.payload.get("issuer", ""),
            event.payload.get("not_after", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                int(event.payload.get("port") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "PORT", "SUBJECT", "ISSUER", "VALID UNTIL"),
        rows,
        cell_subjects=("host", "port", "", "", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TLS certificates ({len(events)})\n{table}"


def render_screenshots_section(context: CommandContext, events: list[Event]) -> str:
    """Render screenshot artifact references as a compact result table."""
    # Screenshot events may include several URLs and artifact records; keep the
    # table scannable by showing the first URLs, screenshot count, and compact
    # artifact references.
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_artifact_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots ({len(events)})\n{table}"


def screenshot_artifact_refs(event: Event) -> str:
    """Return compact artifact references for one screenshot event."""
    refs: list[str] = []
    screenshots = event.payload.get("screenshots", [])
    if not isinstance(screenshots, list):
        return ""
    for screenshot in screenshots:
        if not isinstance(screenshot, dict):
            continue
        ref = screenshot.get("artifact_id") or screenshot.get("artifact") or screenshot.get("path")
        if ref:
            refs.append(str(ref))
    return ", ".join(refs)


def render_smb_shares_section(context: CommandContext, events: list[Event]) -> str:
    """Render SMB shares as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            format_bool(event.payload.get("authenticated")),
            event.payload.get("remark", ""),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("host") or ""),
                str(event.payload.get("share") or ""),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"SMB shares ({len(events)})\n{table}"


def format_bool(value: object) -> str:
    """Format optional bools for result tables."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return ""


def render_route_hops_section(context: CommandContext, events: list[Event]) -> str:
    """Render route traces as a compact result table."""
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("target") or ""),
                int(event.payload.get("hop") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Route hops ({len(events)})\n{table}"


def render_http_paths_section(context: CommandContext, events: list[Event]) -> str:
    """Render HTTP path observations."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("title", ""),
            "yes" if event.payload.get("interesting") else "",
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "TITLE", "INTERESTING"),
        rows,
        cell_subjects=("url", "status", "", "status"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP paths ({len(events)})\n{table}"


def render_web_fingerprints_section(context: CommandContext, events: list[Event]) -> str:
    """Render web technology fingerprints."""
    # Fingerprint payloads can be noisy, so the results view caps displayed
    # technologies and collapses observation details into severity counts.
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            ", ".join(str(value) for value in event.payload.get("technologies", [])[:4]),
            observation_summary(event.payload.get("observations")),
            event.payload.get("server", ""),
            "yes" if event.payload.get("interesting") else "",
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "TECH", "OBSERVATIONS", "SERVER", "INTERESTING"),
        rows,
        cell_subjects=("url", "status", "value", "value", "", "status"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Web fingerprints ({len(events)})\n{table}"


def observation_summary(value: object) -> str:
    """Summarize webfin observation lists for compact result views."""
    if not isinstance(value, list) or not value:
        return ""
    severities: Counter[str] = Counter()
    for item in value:
        if isinstance(item, dict):
            severity = str(item.get("severity") or "unknown")
        else:
            severity = "unknown"
        severities[severity] += 1
    return ", ".join(f"{severity}:{count}" for severity, count in sorted(severities.items()))


def render_waf_section(context: CommandContext, events: list[Event]) -> str:
    """Render WAF or edge protection fingerprints."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("vendor", ""),
            event.payload.get("product", ""),
            event.payload.get("confidence", ""),
            event.payload.get("evidence", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "VENDOR", "PRODUCT", "CONF", "EVIDENCE"),
        rows,
        cell_subjects=("url", "value", "value", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"WAF signals ({len(events)})\n{table}"


def format_rtt(value: object) -> str:
    """Format one route hop round-trip time."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)
