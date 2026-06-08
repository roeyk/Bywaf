"""Report grouping model helpers.

Defines logical finding groups and normalized grouping helpers used by report
rendering and review actions.

Used by:
- analysis.report: render and review grouped finding reports.
- analysis.report.review and analysis.report.render: share one grouping model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from bywaf.event import Event
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


def filter_groups_by_cve(groups: list[FindingGroup], selector: str) -> list[FindingGroup]:
    """Return finding groups matching comma-separated CVE selectors."""
    patterns = cve_patterns(selector)
    if not patterns:
        return groups
    return [group for group in groups if group_matches_cve(group, patterns)]


def cve_patterns(selector: str) -> tuple[str, ...]:
    """Return normalized CVE selector patterns."""
    patterns = tuple(item.strip().upper() for item in selector.split(",") if item.strip())
    related = [pattern for pattern in patterns if pattern.endswith("+")]
    if related:
        raise ValueError(
            "cve=...+ related-CVE expansion requires a CVE relationship provider; "
            "use cve=CVE-YYYY-NNNN for exact matching or cve=CVE-YYYY-* for wildcard matching"
        )
    return patterns


def group_matches_cve(group: FindingGroup, patterns: tuple[str, ...]) -> bool:
    """Return whether one group has any CVE matching the requested patterns."""
    values = group_cve_values(group)
    if not values:
        return False
    return any(cve_value_matches(value, pattern) for value in values for pattern in patterns)


def group_cve_values(group: FindingGroup) -> tuple[str, ...]:
    """Return normalized CVE identifiers from all events in a group."""
    values: list[str] = []
    seen: set[str] = set()
    for event in group.events:
        identifiers = effective_finding_payload(event).get("identifiers")
        if not isinstance(identifiers, Mapping):
            continue
        raw_values = identifiers.get("cve") or identifiers.get("CVE") or ()
        if isinstance(raw_values, str):
            raw_values = (raw_values,)
        if not isinstance(raw_values, Iterable):
            continue
        for raw_value in raw_values:
            value = str(raw_value).strip().upper()
            if value and value not in seen:
                values.append(value)
                seen.add(value)
    return tuple(values)


def cve_value_matches(value: str, pattern: str) -> bool:
    """Return whether a CVE value matches an exact or wildcard selector."""
    return fnmatchcase(value.upper(), pattern.upper())


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
