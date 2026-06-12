"""Saved report scope helpers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from argparse import Namespace
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext


SAVED_REPORT_TOPIC = "report.scope.saved"


def save_report_scope(context: CommandContext, parsed: Namespace, *, action: str) -> None:
    """Persist one named report scope as an append-only event."""
    name = normalized_name(parsed.name)
    selectors = report_scope_selectors(parsed)
    if not selectors:
        raise ValueError(f"report {action} requires job=, pipeline=, or step=")
    existing = saved_report_scope(context, name)
    if action == "create" and existing is not None:
        raise ValueError(f"report scope already exists: {name}")
    context.events.publish(
        SAVED_REPORT_TOPIC,
        {
            "name": name,
            "selectors": selectors,
            "status": parsed.status,
            "sort": parsed.sort,
            "action": action,
        },
    )
    context.output(f"saved report scope name={name} selectors={format_selectors(selectors)}")


def apply_saved_report_scope(context: CommandContext, parsed: Namespace) -> None:
    """Apply one named saved report scope to a parsed report command."""
    saved = saved_report_scope(context, normalized_name(parsed.name))
    if saved is None:
        raise ValueError(f"unknown report scope: {parsed.name}")
    selectors = saved.payload.get("selectors")
    if not isinstance(selectors, dict):
        raise ValueError(f"saved report scope is malformed: {parsed.name}")
    parsed.job = str(selectors.get("job") or "")
    parsed.pipeline = str(selectors.get("pipeline") or "")
    parsed.step = str(selectors.get("step") or "")
    parsed.status = str(saved.payload.get("status") or parsed.status)
    parsed.sort = str(saved.payload.get("sort") or parsed.sort)


def saved_report_scope(context: CommandContext, name: str) -> Event | None:
    """Return the latest saved report scope event by name."""
    matches = [
        event
        for event in context.events.query(topic=SAVED_REPORT_TOPIC, limit=10000)
        if str(event.payload.get("name") or "") == name
    ]
    return max(matches, key=lambda event: event.id or 0) if matches else None


def report_scope_selectors(parsed: Namespace) -> dict[str, str]:
    """Return non-empty runtime selectors from parsed report args."""
    selectors: dict[str, str] = {}
    for key in ("job", "pipeline", "step"):
        value = str(getattr(parsed, key, "") or "").strip()
        if value:
            selectors[key] = value
    return selectors


def format_selectors(selectors: dict[str, Any]) -> str:
    """Return selector text in report command syntax."""
    return " ".join(f"{key}={value}" for key, value in selectors.items())


def normalized_name(value: object) -> str:
    """Return a non-empty saved report name."""
    name = str(value or "").strip()
    if not name:
        raise ValueError("report scope name= is required")
    return name
