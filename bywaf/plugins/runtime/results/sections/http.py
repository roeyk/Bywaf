"""HTTP and web result sections for the results command."""

from __future__ import annotations

from collections import Counter

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width


def render_http_endpoints_section(context: CommandContext, events: list[Event]) -> str:
    """Render reachable HTTP endpoints as a compact result table."""
    # Keep endpoint rows sorted by URL so repeated result views remain stable
    # even when events arrived from parallel or background jobs.
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
    # This is intentionally a short, opinionated checklist for the results
    # overview. Detailed header dictionaries remain available in raw events.
    expected = ("strict-transport-security", "x-content-type-options")
    missing = [header for header in expected if header not in observed]
    return ", ".join(missing)


def render_http_paths_section(context: CommandContext, events: list[Event]) -> str:
    """Render HTTP path observations."""
    # Path probes can produce many rows; the overview highlights title and
    # interesting-state rather than every response header or body snippet.
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
    # Observations are reduced by severity so the result table can show signal
    # density without expanding the full web fingerprint payload.
    for item in value:
        if isinstance(item, dict):
            severity = str(item.get("severity") or "unknown")
        else:
            severity = "unknown"
        severities[severity] += 1
    return ", ".join(f"{severity}:{count}" for severity, count in sorted(severities.items()))


def render_waf_section(context: CommandContext, events: list[Event]) -> str:
    """Render WAF or edge protection fingerprints."""
    # WAF rows preserve the primary evidence string because the same vendor can
    # be detected by very different headers, cookies, or response bodies.
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
