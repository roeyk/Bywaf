"""Network-oriented result sections for the results command.

Used by: `runtime.results.render` and `runtime.results.sections` to render
topic-specific `results` output for hosts, names, ports, banners, services, and
TLS certificates.
"""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.network.portscanner.ports import render_ports
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width
from bywaf.style import styled_subject_text
from .network_media import (
    format_rtt,
    render_route_hops_section,
    render_screenshots_section,
    screenshot_artifact_refs,
)

__all__ = [
    "equivalent_ports_command",
    "format_rtt",
    "render_hosts_section",
    "render_name_resolution_section",
    "render_ports_section",
    "render_route_hops_section",
    "render_screenshots_section",
    "render_services_section",
    "render_tcp_banners_section",
    "render_tls_certificates_section",
    "screenshot_artifact_refs",
]


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
