"""Scope and delta selection helpers for inventory commands."""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import require_job

SCOPE_KEYS = {"all", "job", "pipeline", "step"}
InventoryIdentity = Callable[[Event], set[tuple[Any, ...]]]


def parse_inventory_selectors(tokens: list[str], *, last: bool = False, new: bool = False) -> Namespace:
    """Parse shared inventory scope selectors."""
    scope: dict[str, str] = {}
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"inventory views use selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("inventory selectors must be key=value")
        if key not in SCOPE_KEYS:
            raise ValueError("inventory selectors must be one of: all, job, pipeline, step")
        scope[key] = value
    all_value = scope.get("all", "true")
    if all_value not in {"true", "false"}:
        raise ValueError("inventory all= must be true or false")
    explicit = [key for key in ("job", "pipeline", "step") if key in scope]
    if len(explicit) > 1:
        raise ValueError("inventory accepts only one runtime scope: job=, pipeline=, or step=")
    if explicit and "all" in scope:
        raise ValueError("inventory all= cannot be combined with job=, pipeline=, or step=")
    if last and new:
        raise ValueError("inventory accepts only one of --last or --new")
    if (last or new) and scope.get("all") == "true":
        raise ValueError("inventory all=true cannot be combined with --last or --new")
    return Namespace(scope=scope, last=last, new=new)


def select_inventory_events(
    context: CommandContext,
    topics: tuple[str, ...],
    selectors: Namespace,
    identity: InventoryIdentity,
) -> list[Event]:
    """Return matching inventory events for the selected scope."""
    scope = selectors.scope
    if selectors.new:
        scoped = latest_inventory_scope_events(context, topics) if not scope else select_inventory_scope_events(context, topics, selectors)
        return events_new_to_scope(context, topics, scoped, identity)
    if selectors.last:
        return latest_inventory_scope_events(context, topics)
    return select_inventory_scope_events(context, topics, selectors)


def select_inventory_scope_events(context: CommandContext, topics: tuple[str, ...], selectors: Namespace) -> list[Event]:
    """Return inventory events for an explicit scope or all project facts."""
    events = context.event_store("inventory")
    runtime = context.runtime_store("inventory")
    scope = selectors.scope
    if "job" in scope:
        if scope["job"] == "latest":
            return latest_inventory_scope_events(context, topics)
        row = require_job(context, scope["job"])
        return [event for event in events.events_for_job(row["id"], limit=10000) if event.topic in topics]
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return [event for event in events.events_matching(pipeline_id=pipeline_id, limit=10000) if event.topic in topics]
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return [event for event in events.events_matching(command_run_id=run_id, limit=10000) if event.topic in topics]
    rows: list[Event] = []
    for topic in topics:
        rows.extend(events.events_matching(topic=topic, limit=10000))
    return sorted(rows, key=lambda event: event.id or 0)


def latest_inventory_scope_events(context: CommandContext, topics: tuple[str, ...]) -> list[Event]:
    """Return events from the newest productive step for these inventory topics."""
    events = context.event_store("inventory latest")
    for event in reversed(events_matching_topics(context, topics, limit=10000)):
        if event.command_run_id:
            return [row for row in events.events_matching(command_run_id=event.command_run_id, limit=10000) if row.topic in topics]
        if event.pipeline_id:
            return [row for row in events.events_matching(pipeline_id=event.pipeline_id, limit=10000) if row.topic in topics]
    return []


def events_new_to_scope(
    context: CommandContext,
    topics: tuple[str, ...],
    scoped: list[Event],
    identity: InventoryIdentity,
) -> list[Event]:
    """Filter scoped events to facts not present before the selected scope."""
    if not scoped:
        return []
    first_id = min((event.id or 0) for event in scoped)
    previous_keys = {
        key
        for event in events_matching_topics(context, topics, limit=10000)
        if (event.id or 0) < first_id
        for key in identity(event)
    }
    seen: set[tuple[Any, ...]] = set()
    result: list[Event] = []
    for event in sorted(scoped, key=lambda row: row.id or 0):
        keys = identity(event)
        if keys and any(key not in previous_keys and key not in seen for key in keys):
            result.append(event)
            seen.update(keys)
    return result


def events_matching_topics(context: CommandContext, topics: tuple[str, ...], *, limit: int) -> list[Event]:
    """Return events for multiple topics in event order."""
    store = context.event_store("inventory topics")
    rows: list[Event] = []
    for topic in topics:
        rows.extend(store.events_matching(topic=topic, limit=limit))
    return sorted(rows, key=lambda event: event.id or 0)


def inventory_scope_label(selectors: Namespace) -> str:
    """Return a short operator-facing scope label."""
    scope = selectors.scope
    prefix = "new in " if selectors.new else ""
    if selectors.last:
        prefix = "latest "
    if "job" in scope:
        return f"{prefix}job={scope['job']}"
    if "pipeline" in scope:
        return f"{prefix}pipeline={scope['pipeline']}"
    if "step" in scope:
        return f"{prefix}step={scope['step']}"
    if selectors.new:
        return "new since prior inventory"
    if selectors.last:
        return "latest inventory-producing step"
    return "project inventory"
