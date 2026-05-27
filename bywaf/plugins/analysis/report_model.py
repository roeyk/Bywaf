"""Report grouping model helpers.

Defines logical finding groups and normalized grouping helpers used by report
rendering and review actions.

Used by:
- analysis.report: render and review grouped finding reports.
- analysis.report_review and analysis.report_render: share one grouping model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from bywaf.events import Event
from bywaf.finding.grouping import finding_group_key as derive_finding_group_key


@dataclass(frozen=True)
class FindingGroup:
    """A derived reporting group for one logical finding."""

    finding_id: str
    events: tuple[Event, ...]

    @property
    def representative(self) -> Event:
        """Return the newest event to render for this group."""
        return max(self.events, key=lambda event: event.id or 0)


def group_finding_events(events: list[Event]) -> list[FindingGroup]:
    """Return derived finding groups keyed by normalized finding id."""
    grouped: dict[str, list[Event]] = {}
    ordered_keys: list[str] = []
    for event in events:
        # Preserve first-seen group order for stable row numbers, then sort each
        # group's events chronologically so the representative can be chosen
        # deterministically.
        key = finding_group_key(event)
        if key not in grouped:
            grouped[key] = []
            ordered_keys.append(key)
        grouped[key].append(event)
    return [
        FindingGroup(key, tuple(sorted(grouped[key], key=lambda event: event.id or 0)))
        for key in ordered_keys
    ]


def finding_group_key(event: Event) -> str:
    """Return the stable grouping key for one finding event."""
    payload = effective_finding_payload(event)
    key = derive_finding_group_key(payload, fallback="")
    if key:
        return key
    if event.id is not None:
        return f"event:{event.id}"
    return f"event:{id(event)}"


def effective_finding_payload(event: Event) -> Mapping[str, Any]:
    """Return the reportable finding payload for raw or merge-candidate events."""
    if event.topic == "finding.merge_candidate":
        candidate = event.payload.get("candidate")
        if isinstance(candidate, Mapping):
            return candidate
    return event.payload


def events_for_groups(groups: list[FindingGroup]) -> list[Event]:
    """Return sorted events from the selected report groups."""
    return sort_unique_events(event for group in groups for event in group.events)


def sort_unique_events(events: Iterable[Event]) -> list[Event]:
    """Return events de-duplicated by id and ordered chronologically."""
    by_id: dict[int, Event] = {}
    no_id: list[Event] = []
    for event in events:
        if event.id is None:
            no_id.append(event)
        else:
            by_id[event.id] = event
    return [*sorted(by_id.values(), key=lambda event: event.id or 0), *no_id]
