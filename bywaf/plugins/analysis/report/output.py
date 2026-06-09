"""Report output and audit-event helpers.

Used by: `analysis.report.render` after it has assembled report text and row
metadata for operator-facing report views.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Mapping

from bywaf.event import Event
from bywaf.plugin import CommandContext

from .model import FindingGroup
from .render_summary import report_rendered_payload


def emit_report_output(context: CommandContext, lines: list[str], parsed: Namespace) -> None:
    """Page or print one complete rendered report.

    Called by: report renderers once all sections have been assembled.
    """
    rendered = "\n".join(line for line in lines if line)
    if page_enabled(parsed.page):
        context.page_text(rendered)
    else:
        context.output(rendered)


def publish_report_rendered(
    context: CommandContext,
    parsed: Namespace,
    events: list[Event],
    *,
    groups: list[FindingGroup] | None,
    rows: int,
    counts: Mapping[str, int] | None,
    action: str | None = None,
) -> None:
    """Publish the `report.rendered` audit event for one report view.

    Called by: report renderers after emitting the operator-facing report text.
    """
    context.events.publish(
        "report.rendered",
        report_rendered_payload(
            parsed,
            events,
            groups=groups or [],
            rows=rows,
            counts=counts,
            action=action,
        ),
    )


def page_enabled(value: object) -> bool:
    """Parse a selector-style page flag such as `page=false`.

    Called by: `emit_report_output()` for report output routing.
    """
    normalized = str(value).strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value}")
