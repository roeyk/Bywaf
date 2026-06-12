"""Scope and delta selection helpers for inventory commands.

Used by: runtime inventory views to interpret `job=`, `pipeline=`, `step=`,
`--last`, and `--new` consistently across host, web, WAF, and related views.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Callable
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import require_job

SCOPE_KEYS = {"all", "job", "pipeline", "step"}
InventoryIdentity = Callable[[Event], set[tuple[Any, ...]]]


def parse_inventory_selectors(
    tokens: list[str],
    *,
    last: bool = False,
    new: bool = False,
    sort_keys: tuple[str, ...] = (),
) -> Namespace:
    """Parse shared inventory scope selectors.

    Called by: inventory commandlets before they query event data.
    """
    scope: dict[str, str] = {}
    sort = sort_keys[0] if sort_keys else ""
    for token in tokens:
        key, value = parse_inventory_selector_token(token)
        # `sort=` affects rendering only; all other key=value tokens define
        # runtime scope and are validated as mutually exclusive selectors.
        if key == "sort":
            sort = parse_inventory_sort(value, sort_keys)
            continue
        require_inventory_scope_key(key)
        scope[key] = value
    validate_inventory_scope(scope, last=last, new=new)
    return Namespace(scope=scope, last=last, new=new, sort=sort)


def parse_inventory_selector_token(token: str) -> tuple[str, str]:
    """Return the key/value pair for one inventory selector token.

    Called by: `parse_inventory_selectors()` for every non-option token passed
    to an inventory commandlet.
    """
    if token.startswith("--"):
        raise ValueError(f"inventory views use selector syntax; use key=value, not {token}")
    key, separator, value = token.partition("=")
    if not separator or not key or not value:
        raise ValueError("inventory selectors must be key=value")
    return key, value


def parse_inventory_sort(value: str, sort_keys: tuple[str, ...]) -> str:
    """Validate and return one inventory sort selector.

    Called by: `parse_inventory_selectors()` when it sees `sort=...`.
    """
    descending = value.startswith("-")
    sort_name = value[1:] if descending else value
    if sort_name not in sort_keys:
        raise ValueError(f"inventory sort= must be one of: {', '.join(sort_keys)}")
    return value


def require_inventory_scope_key(key: str) -> None:
    """Validate that an inventory selector key is supported.

    Called by: `parse_inventory_selectors()` before adding a selector to the
    runtime scope dictionary.
    """
    if key not in SCOPE_KEYS:
        allowed = ", ".join((*sorted(SCOPE_KEYS), "sort"))
        raise ValueError(f"inventory selectors must be one of: {allowed}")


def validate_inventory_scope(scope: dict[str, str], *, last: bool, new: bool) -> None:
    """Validate combined inventory scope selectors.

    Called by: `parse_inventory_selectors()` after individual key=value tokens
    have been parsed.
    """
    all_value = scope.get("all", "true")
    if all_value not in {"true", "false"}:
        raise ValueError("inventory all= must be true or false")
    # job/pipeline/step are mutually exclusive runtime selectors. Keeping that
    # invariant here makes each inventory renderer receive one clear event set.
    explicit = [key for key in ("job", "pipeline", "step") if key in scope]
    if len(explicit) > 1:
        raise ValueError("inventory accepts only one runtime scope: job=, pipeline=, or step=")
    if explicit and "all" in scope:
        raise ValueError("inventory all= cannot be combined with job=, pipeline=, or step=")
    if last and new:
        raise ValueError("inventory accepts only one of --last or --new")
    if (last or new) and scope.get("all") == "true":
        raise ValueError("inventory all=true cannot be combined with --last or --new")


def select_inventory_events(
    context: CommandContext,
    topics: tuple[str, ...],
    selectors: Namespace,
    identity: InventoryIdentity,
) -> list[Event]:
    """Return matching inventory events for the selected scope.

    Called by: shared inventory commandlet execution before invoking the
    view-specific renderer.
    """
    # `--new` is evaluated first because it compares a selected scope against
    # earlier project facts. `--last` is a simpler latest-step shortcut.
    if selectors.new:
        return select_new_inventory_events(context, topics, selectors, identity)
    if selectors.last:
        return latest_inventory_scope_events(context, topics)
    return select_inventory_scope_events(context, topics, selectors)


def select_new_inventory_events(
    context: CommandContext,
    topics: tuple[str, ...],
    selectors: Namespace,
    identity: InventoryIdentity,
) -> list[Event]:
    """Return facts from the selected scope that did not exist before it.

    Called by: `select_inventory_events()` for `--new` inventory views.
    """
    scoped = latest_inventory_scope_events(context, topics)
    if selectors.scope:
        scoped = select_inventory_scope_events(context, topics, selectors)
    return events_new_to_scope(context, topics, scoped, identity)


def select_inventory_scope_events(context: CommandContext, topics: tuple[str, ...], selectors: Namespace) -> list[Event]:
    """Return inventory events for an explicit scope or all project facts.

    Used by: normal inventory views and as the scoped side of `--new` when an
    explicit job, pipeline, or step was requested.
    """
    scope = selectors.scope
    if "job" in scope:
        return events_for_job_scope(context, topics, scope["job"])
    if "pipeline" in scope:
        return events_for_pipeline_scope(context, topics, scope["pipeline"])
    if "step" in scope:
        return events_for_step_scope(context, topics, scope["step"])
    return events_matching_topics(context, topics, limit=10000)


def events_for_job_scope(context: CommandContext, topics: tuple[str, ...], job: str) -> list[Event]:
    """Return inventory events from one job scope.

    Called by: `select_inventory_scope_events()` for `job=...`.
    """
    if job == "latest":
        return latest_inventory_scope_events(context, topics)
    events = context.event_store("inventory")
    row = require_job(context, job)
    return events.events_for_job_topics(row["id"], topics, limit=10000)


def events_for_pipeline_scope(context: CommandContext, topics: tuple[str, ...], pipeline: str) -> list[Event]:
    """Return inventory events from one pipeline scope.

    Called by: `select_inventory_scope_events()` for `pipeline=...`.
    """
    runtime = context.runtime_store("inventory")
    pipeline_id = runtime.resolve_pipeline_serial(pipeline)
    return events_matching_topics(context, topics, pipeline=pipeline_id, limit=10000)


def events_for_step_scope(context: CommandContext, topics: tuple[str, ...], step: str) -> list[Event]:
    """Return inventory events from one command-run scope.

    Called by: `select_inventory_scope_events()` for `step=...`.
    """
    runtime = context.runtime_store("inventory")
    run_id = runtime.resolve_run_serial(step)
    return events_matching_topics(context, topics, step=run_id, limit=10000)


def latest_inventory_scope_events(context: CommandContext, topics: tuple[str, ...]) -> list[Event]:
    """Return events from the newest productive step for these inventory topics.

    Used by: `--last`, `--new`, and `job=latest` inventory views.
    """
    for event in reversed(events_matching_topics(context, topics, limit=10000)):
        # Prefer a concrete command-run scope. Fall back to pipeline scope for
        # older or externally inserted events that lack command_run_id.
        if event.command_run_id:
            return events_matching_topics(context, topics, step=event.command_run_id, limit=10000)
        if event.pipeline_id:
            return events_matching_topics(context, topics, pipeline=event.pipeline_id, limit=10000)
    return []


def events_new_to_scope(
    context: CommandContext,
    topics: tuple[str, ...],
    scoped: list[Event],
    identity: InventoryIdentity,
) -> list[Event]:
    """Filter scoped events to facts not present before the selected scope.

    The caller supplies an identity extractor because each inventory view has a
    different notion of sameness: host, endpoint, WAF name, screenshot target,
    certificate subject, and so on.
    """
    if not scoped:
        return []
    first_id = min((event.id or 0) for event in scoped)
    # Build the baseline set from events before the scoped run, then keep only
    # first-seen identities from the selected scope.
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


def events_matching_topics(
    context: CommandContext,
    topics: tuple[str, ...],
    *,
    step: str | None = None,
    pipeline: str | None = None,
    limit: int,
) -> list[Event]:
    """Return events for multiple topics in event order.

    Called by: inventory scope helpers whenever an event-store query is needed.
    """
    store = context.event_store("inventory topics")
    rows: list[Event] = []
    # Query per topic because the store API is topic-centric, then re-sort so
    # mixed-topic inventory views preserve original event chronology.
    for topic in topics:
        rows.extend(store.events_matching(topic=topic, command_run_id=step, pipeline_id=pipeline, limit=limit))
    return sorted(rows, key=lambda event: event.id or 0)


def inventory_scope_label(selectors: Namespace) -> str:
    """Return a short operator-facing scope label.

    Called by: inventory commandlets after event selection so renderers can put
    the selected scope in their table headings.
    """
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
