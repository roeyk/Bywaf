"""Event-sourced bundle state reconstruction helpers.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from typing import Any

from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.bundle.model import Bundle


def all_bundles(context: CommandContext) -> dict[str, Bundle]:
    """Reconstruct bundles from durable events.

    Called by: bundle list/show/action helpers and completion logic.
    """
    events = context.event_store("bundle").events_matching(limit=100000)
    bundles: dict[str, Bundle] = {}
    item_map: dict[str, list[dict[str, Any]]] = {}
    sealed: dict[str, dict[str, Any]] = {}
    for event in events:
        # Bundle state is event-sourced so sealed bundles remain auditable and
        # can be reconstructed even after process restart.
        name = event.payload.get("name")
        if not isinstance(name, str):
            continue
        if event.topic == "bundle.created":
            bundles[name] = Bundle(
                name=name,
                bundle_id=str(event.payload.get("bundle_id", "")),
                created_at=event.created_at.isoformat(),
                items=(),
            )
        elif event.topic == "bundle.item.added":
            item_map.setdefault(name, []).append(dict(event.payload))
        elif event.topic == "bundle.sealed":
            sealed[name] = dict(event.payload)
    return {
        name: Bundle(
            name=bundle.name,
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            items=tuple(item_map.get(name, [])),
            sealed=sealed.get(name),
        )
        for name, bundle in bundles.items()
    }


def bundle_by_name(context: CommandContext, name: str) -> Bundle | None:
    """Return a bundle by name if it exists."""
    return all_bundles(context).get(name)


def require_bundle(context: CommandContext, name: str) -> Bundle:
    """Return a bundle or raise a user-facing error."""
    bundle = bundle_by_name(context, name)
    if bundle is None:
        raise ValueError(f"unknown bundle: {name}")
    return bundle
