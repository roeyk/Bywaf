"""Delta selection helpers for report inventory views."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext


def new_topic_events(context: CommandContext, topics: tuple[str, ...], identity, *, limit: int) -> list[Event]:
    """Return facts from the latest productive scope that were not known before it."""
    scoped = latest_topic_events(context, topics, limit=limit)
    if not scoped:
        return []
    # Treat the first event in the latest productive scope as the boundary.
    # Anything with a matching identity before that point is historical context,
    # not newly discovered signal for this report.
    first_id = min((event.id or 0) for event in scoped)
    previous_keys = {
        key
        for event in events_for_topics(context, topics, limit=limit)
        if (event.id or 0) < first_id
        for key in identity(event)
    }
    seen: set[tuple[object, ...]] = set()
    result: list[Event] = []
    for event in scoped:
        keys = identity(event)
        # Keep only the first event for each new identity inside the selected
        # scope. This prevents duplicate rows when multiple topics describe the
        # same host, service, URL, or finding.
        if any(key not in previous_keys and key not in seen for key in keys):
            result.append(event)
            seen.update(keys)
    return result


def latest_topic_events(context: CommandContext, topics: tuple[str, ...], *, limit: int) -> list[Event]:
    """Return events for the newest step that produced one of the given topics."""
    events = events_for_topics(context, topics, limit=limit)
    for event in reversed(events):
        # Prefer the newest command run as the productive unit. Fall back to the
        # pipeline when older or externally inserted events lack step metadata.
        if event.command_run_id:
            return events_for_topics(context, topics, step=event.command_run_id, limit=limit)
        if event.pipeline_id:
            return events_for_topics(context, topics, pipeline=event.pipeline_id, limit=limit)
    return []


def events_for_topics(
    context: CommandContext,
    topics: tuple[str, ...],
    *,
    step: str | None = None,
    pipeline: str | None = None,
    limit: int,
) -> list[Event]:
    """Query multiple topics and return event-ordered results."""
    events: list[Event] = []
    for topic in topics:
        # Query topics separately because the event service accepts one topic at
        # a time; sorted_unique() reassembles a chronological multi-topic view.
        events.extend(context.events.query(topic=topic, step=step, pipeline=pipeline, limit=limit))
    return sorted_unique(events)


def host_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable host identities for report delta comparisons."""
    host = str(event.payload.get("host") or "").strip()
    return {("host", host)} if host else set()


def service_event_keys(event: Event) -> set[tuple[str, str, int, str]]:
    """Return stable service identities for report delta comparisons."""
    payload = event.payload
    host = str(payload.get("host") or "").strip()
    if not host:
        return set()
    # HTTP/TLS endpoint facts may omit a port but include a scheme. Normalize
    # those to conventional ports so repeat observations compare correctly.
    port = int(payload.get("port") or default_port(payload))
    protocol = str(payload.get("protocol") or "tcp")
    return {("service", host, port, protocol)}


def web_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable web identities for report delta comparisons."""
    payload = event.payload
    values: set[str] = set()
    url = payload.get("url")
    if isinstance(url, str) and url:
        values.add(url)
    urls = payload.get("urls")
    if isinstance(urls, list):
        values.update(str(item) for item in urls if item)
    host = payload.get("ip") or payload.get("host")
    if event.topic == "network.route.hop" and host:
        # Route hops are host-like network context even though they do not have
        # URL fields.
        values.add(str(host))
    return {("web", value) for value in values}


def finding_event_keys(event: Event) -> set[tuple[str, str]]:
    """Return stable finding identities for report delta comparisons."""
    payload = event.payload
    finding_id = str(payload.get("finding_id") or "").strip()
    if finding_id:
        return {("finding", finding_id)}
    title = str(payload.get("title") or payload.get("class") or "").strip()
    target = str(payload.get("target_scope") or payload.get("target") or payload.get("affected") or "").strip()
    # Some scanner facts predate stable finding_id support. Title plus target
    # is the fallback identity used only when a first-class id is absent.
    return {("finding", f"{title}|{target}")} if title or target else set()


def default_port(payload: dict) -> int:
    """Return the implied port for common web schemes."""
    scheme = str(payload.get("scheme") or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return 0


def sorted_unique(events: list[Event]) -> list[Event]:
    """Return events in id order without duplicates."""
    seen: set[int] = set()
    result: list[Event] = []
    for event in sorted(events, key=lambda item: item.id or 0):
        # In-memory test events may not have database ids. Use object identity
        # in that case while preserving database-id behavior for real events.
        marker = event.id if event.id is not None else id(event)
        if marker not in seen:
            result.append(event)
            seen.add(marker)
    return result
