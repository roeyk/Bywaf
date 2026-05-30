"""Audit selector parsing and event-window filtering.

Resolves `topic=`, `job=`, `pipeline=`, `step=`, `serial=`, `since=`, and
`until=` selectors into concrete event-store queries.

Used by:
- runtime.audit: implement `audit show`.
- runtime.audit.export: select records for export."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, time

from bywaf.event import Event
from bywaf.plugin import CommandContext

from .common import AUDIT_LIST_SELECTORS, AUDIT_LIST_TARGETS, AUDIT_SELECTORS


def parse_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse key=value selector tokens into a dictionary."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError(f"invalid audit selector: {token}")
        key, value = token.split("=", 1)
        if key not in AUDIT_SELECTORS:
            raise ValueError(f"unknown audit selector: {key}")
        if not value:
            raise ValueError(f"audit selector {key}= requires a value")
        selectors[key] = value
    return selectors


def parse_list_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse `audit list <target> [key=value]` selectors."""
    if not tokens:
        raise ValueError("audit list requires a target")
    target, *rest = tokens
    if target not in AUDIT_LIST_TARGETS:
        raise ValueError(f"unknown audit list target: {target}")
    selectors = {"_target": target}
    for token in rest:
        if "=" not in token:
            raise ValueError(f"invalid audit list selector: {token}")
        key, value = token.split("=", 1)
        if key not in AUDIT_LIST_SELECTORS:
            raise ValueError(f"unknown audit list selector: {key}")
        if not value:
            raise ValueError(f"audit list selector {key}= requires a value")
        selectors[key] = value
    return selectors


def require_selector(selectors: dict[str, str], name: str) -> str:
    """Return a required selector value or raise a user-facing error."""
    try:
        return selectors[name]
    except KeyError as exc:
        raise ValueError(f"audit {name}= is required") from exc


def selected_events(context: CommandContext, selectors: dict[str, str], limit: int) -> list[Event]:
    """Fetch events matching audit selectors."""
    events_store = context.event_store("audit")
    # serial= and job= require helper lookups because they may span several
    # event columns. Direct topic/step/pipeline selection can use the generic
    # event query path.
    if "serial" in selectors:
        events = events_store.events_for_serial(selectors["serial"], limit=100000)
    elif "job" in selectors:
        events = events_store.events_for_job(resolve_job_selector(context, selectors["job"]), limit=100000)
    else:
        events = events_store.events_matching(
            topic=selectors.get("topic"),
            command_run_id=resolve_run_selector(context, selectors.get("step")),
            pipeline_id=resolve_pipeline_selector(context, selectors.get("pipeline")),
            limit=100000,
        )
    window = audit_window(context, selectors)
    return [event for event in events if event_in_window(event, window)][:limit]


def audit_window(
    context: CommandContext,
    selectors: dict[str, str],
) -> tuple[int | None, int | None, datetime | None, datetime | None]:
    """Resolve since/until selectors to event-id or timestamp bounds."""
    since_id, since_time = resolve_bound(context, selectors.get("since"), since=True)
    until_id, until_time = resolve_bound(context, selectors.get("until"), since=False)
    return since_id, until_id, since_time, until_time


def resolve_bound(
    context: CommandContext,
    value: str | None,
    *,
    since: bool,
) -> tuple[int | None, datetime | None]:
    """Resolve one audit time-window bound."""
    if value is None:
        return None, None
    kind, raw = split_bound(value)
    # Bounds can be wall-clock timestamps or runtime-relative anchors such as
    # since=step:3. Resolve both to either event IDs or datetimes, then apply one
    # common event_in_window predicate.
    resolver = audit_bound_resolvers().get(kind)
    if resolver is None:
        raise ValueError(f"unsupported audit bound type: {kind}")
    return resolver(context, raw, since=since)


AuditBoundResolver = Callable[..., tuple[int | None, datetime | None]]


def audit_bound_resolvers() -> dict[str, AuditBoundResolver]:
    """Return audit since/until bound resolvers keyed by selector type."""
    return {
        "job": resolve_job_bound,
        "pipeline": resolve_pipeline_bound,
        "step": resolve_run_bound,
        "time": resolve_time_bound,
    }


def resolve_time_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a compact timestamp audit bound."""
    del context
    return None, parse_compact_time(raw, until=not since)


def resolve_run_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a step-relative audit bound."""
    return entity_event_id(
        context,
        command_run_id=context.runtime_store("audit").resolve_run_serial(raw),
        first=since,
    ), None


def resolve_pipeline_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a pipeline-relative audit bound."""
    return entity_event_id(
        context,
        pipeline_id=context.runtime_store("audit").resolve_pipeline_serial(raw),
        first=since,
    ), None


def resolve_job_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a job-relative audit bound."""
    events = context.event_store("audit").events_for_job(resolve_job_selector(context, raw), limit=100000)
    if not events:
        raise ValueError(f"unknown audit job bound: {raw}")
    return (events[0].id if since else events[-1].id), None


def resolve_job_selector(context: CommandContext, value: str) -> int:
    """Resolve a local job id or durable job serial to a local job id."""
    try:
        return int(value)
    except ValueError:
        resolved = context.runtime_store("audit").job_id_for_serial(value)
        if resolved is None:
            raise ValueError(f"unknown job: {value}") from None
        return int(resolved)


def split_bound(value: str) -> tuple[str, str]:
    """Split `kind:value`, defaulting unqualified values to `time`."""
    if ":" not in value:
        return "time", value
    kind, raw = value.split(":", 1)
    if not raw:
        raise ValueError(f"audit {kind}: bound requires a value")
    return kind, raw


def parse_compact_time(value: str, *, until: bool) -> datetime:
    """Parse yyyymmdd[HH[MM[SS]]] into a datetime bound."""
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) not in {8, 10, 12, 14}:
        raise ValueError("audit time must be yyyymmdd[HH[MM[SS]]]")
    year = int(digits[:4])
    month = int(digits[4:6])
    day = int(digits[6:8])
    hour = int(digits[8:10]) if len(digits) >= 10 else (23 if until else 0)
    minute = int(digits[10:12]) if len(digits) >= 12 else (59 if until else 0)
    second = int(digits[12:14]) if len(digits) >= 14 else (59 if until else 0)
    return datetime.combine(datetime(year, month, day).date(), time(hour, minute, second))


def entity_event_id(
    context: CommandContext,
    *,
    command_run_id: str | None = None,
    pipeline_id: str | None = None,
    first: bool,
) -> int:
    """Return the first or last event ID for a step or pipeline bound."""
    events = context.event_store("audit").events_matching(
        command_run_id=command_run_id,
        pipeline_id=pipeline_id,
        limit=100000,
    )
    label = f"step {command_run_id}" if command_run_id else f"pipeline {pipeline_id}"
    if not events:
        raise ValueError(f"unknown audit bound: {label}")
    event_id = events[0].id if first else events[-1].id
    if event_id is None:
        raise ValueError(f"audit bound has no event id: {label}")
    return event_id


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing step id to a durable step serial."""
    if value is None:
        return None
    return context.runtime_store("audit").resolve_run_serial(value)


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing pipeline id to a durable pipeline serial."""
    if value is None:
        return None
    return context.runtime_store("audit").resolve_pipeline_serial(value)


def event_in_window(
    event: Event,
    window: tuple[int | None, int | None, datetime | None, datetime | None],
) -> bool:
    """Return whether an event falls within resolved audit bounds."""
    since_id, until_id, since_time, until_time = window
    event_id = event.id or 0
    created = event.created_at.replace(tzinfo=None)
    return (
        (since_id is None or event_id >= since_id)
        and (until_id is None or event_id <= until_id)
        and (since_time is None or created >= since_time)
        and (until_time is None or created <= until_time)
    )
