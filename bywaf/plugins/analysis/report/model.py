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
    patterns = cve_patterns(selector, groups)
    if not patterns:
        return groups
    return [group for group in groups if group_matches_cve(group, patterns)]


def cve_patterns(selector: str, groups: list[FindingGroup] | None = None) -> tuple[str, ...]:
    """Return normalized CVE selector patterns."""
    patterns: list[str] = []
    for item in selector.split(","):
        pattern = item.strip().upper()
        if pattern:
            patterns.extend(expand_cve_pattern(pattern, groups or ()))
    return tuple(patterns)


def expand_cve_pattern(pattern: str, groups: Iterable[FindingGroup]) -> tuple[str, ...]:
    """Expand one CVE selector pattern."""
    if not pattern.endswith("+"):
        return (pattern,)
    root = pattern[:-1]
    if not root or "*" in root:
        raise ValueError("cve=...+ requires one exact CVE before the + suffix")
    expanded = related_cve_patterns(root, groups)
    if not expanded:
        raise ValueError(f"cve={root}+ has no related CVEs in scoped finding/advisory events")
    return expanded


def related_cve_patterns(root: str, groups: Iterable[FindingGroup]) -> tuple[str, ...]:
    """Return one root CVE plus related CVEs found in scoped event metadata."""
    values = [root]
    seen = {root}
    for group in groups:
        for event in group.events:
            payload = effective_finding_payload(event)
            cves = payload_cve_values(payload)
            if root not in cves:
                continue
            for related in payload_related_cves(payload):
                if related not in seen:
                    values.append(related)
                    seen.add(related)
    return tuple(values) if len(values) > 1 else ()


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
        for value in payload_cve_values(effective_finding_payload(event)):
            if value not in seen:
                values.append(value)
                seen.add(value)
    return tuple(values)


def cve_value_matches(value: str, pattern: str) -> bool:
    """Return whether a CVE value matches an exact or wildcard selector."""
    return fnmatchcase(value.upper(), pattern.upper())


def payload_cve_values(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Return normalized primary CVEs from a finding or advisory payload."""
    identifiers = payload.get("identifiers")
    if not isinstance(identifiers, Mapping):
        return ()
    return normalized_values(identifiers.get("cve") or identifiers.get("CVE") or ())


def payload_related_cves(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Return normalized related CVEs from a finding or advisory payload."""
    identifiers = payload.get("identifiers")
    if isinstance(identifiers, Mapping):
        values = normalized_values(
            identifiers.get("related_cves")
            or identifiers.get("related_cve")
            or identifiers.get("related")
            or ()
        )
        if values:
            return values
    return normalized_values(payload.get("related_cves") or payload.get("related_cve") or ())


def normalized_values(raw_values: Any) -> tuple[str, ...]:
    """Return normalized unique string values from scalar or iterable metadata."""
    if isinstance(raw_values, str):
        raw_values = (raw_values,)
    if not isinstance(raw_values, Iterable):
        return ()
    values: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        value = str(raw_value).strip().upper()
        if value and value not in seen:
            values.append(value)
            seen.add(value)
    return tuple(values)


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
