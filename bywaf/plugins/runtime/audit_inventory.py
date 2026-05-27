"""Capability inventory reporting for audit commandlets.

Compares manifest declarations with runtime capability audit events so
operators can spot missing or overly broad capabilities.

Used by:
- runtime.audit: implement `audit list capabilities`."""

from __future__ import annotations

from bywaf.events import Event
from bywaf.plugin import CommandContext
from bywaf.plugin.capabilities import implied_capabilities
from bywaf.registry import PluginRegistry
from bywaf.time_format import format_operator_timestamp


def capability_inventory_rows(context: CommandContext, *, plugin_filter: str | None = None) -> list[dict[str, str]]:
    """Return declaration/runtime inventory rows for framework capabilities."""
    runner = context.metadata.get("runner")
    registry = runner.registry if runner is not None else PluginRegistry.discover()
    # Compare manifest/spec declarations with actual capability audit events.
    # This gives operators a quick view of drift between what plugins claimed
    # and what they attempted during execution.
    declared = declared_capabilities(registry, plugin_filter=plugin_filter)
    used = capability_events(context, "plugin.capability.used", plugin_filter=plugin_filter)
    missing = capability_events(context, "plugin.capability.missing", plugin_filter=plugin_filter)
    names = sorted(set(declared) | set(used) | set(missing))
    return [capability_inventory_row(name, declared, used, missing) for name in names]


def declared_capabilities(registry: PluginRegistry, *, plugin_filter: str | None = None) -> dict[str, list[str]]:
    """Return declared capability names mapped to declaring commandlets."""
    declarations: dict[str, list[str]] = {}
    plugins = registry.plugins
    if plugin_filter is not None:
        if plugin_filter not in plugins:
            raise ValueError(f"unknown plugin for capability inventory: {plugin_filter}")
        plugins = {plugin_filter: plugins[plugin_filter]}
    for name, plugin in plugins.items():
        for capability in implied_capabilities(plugin.spec):
            declarations.setdefault(capability, []).append(name)
    return {capability: sorted(names) for capability, names in declarations.items()}


def capability_events(
    context: CommandContext,
    topic: str,
    *,
    plugin_filter: str | None = None,
) -> dict[str, list[Event]]:
    """Return capability audit events grouped by capability."""
    grouped: dict[str, list[Event]] = {}
    for event in context.event_store("audit").events_for_topic(topic, limit=100000):
        commandlet = str(event.payload.get("commandlet") or event.source)
        if plugin_filter is not None and commandlet != plugin_filter:
            continue
        capability = event.payload.get("capability")
        if not isinstance(capability, str) or not capability:
            continue
        grouped.setdefault(capability, []).append(event)
    return grouped


def capability_inventory_row(
    capability: str,
    declared: dict[str, list[str]],
    used: dict[str, list[Event]],
    missing: dict[str, list[Event]],
) -> dict[str, str]:
    """Build one printable capability inventory row."""
    used_events = used.get(capability, [])
    missing_events = missing.get(capability, [])
    last_event = used_events[-1] if used_events else None
    status = capability_status(capability, declared, used_events, missing_events)
    return {
        "Capability": capability,
        "Range": capability_range(capability),
        "Declared By": ", ".join(declared.get(capability, ())) or "-",
        "Last Used": format_event_time(last_event) if last_event is not None else "never",
        "Last User": str(last_event.payload.get("commandlet") or last_event.source) if last_event is not None else "-",
        "Missing": str(len(missing_events)),
        "Status": status,
    }


def capability_status(
    capability: str,
    declared: dict[str, list[str]],
    used_events: list[Event],
    missing_events: list[Event],
) -> str:
    """Return a compact status label for one capability."""
    if missing_events and capability not in declared:
        return "missing"
    if capability.endswith(":*"):
        return "broad"
    if used_events:
        return "observed"
    if capability in declared:
        return "declared-only"
    return "unknown"


def capability_range(capability: str) -> str:
    """Return the accepted capability-code family range for a capability."""
    if capability.startswith("db.read:") or capability.startswith("db.write:"):
        return "C100-C199"
    if capability.startswith("db.") or capability.startswith("artifact."):
        return "C200-C299"
    if capability.startswith("process.") or capability.startswith("filesystem."):
        return "C300-C399"
    if capability.startswith("network."):
        return "C400-C499"
    if capability.startswith("framework.secret"):
        return "C500-C599"
    if capability.startswith("framework.job") or capability.startswith("framework.pipeline"):
        return "C600-C699"
    if capability.startswith("framework.render"):
        return "C700-C799"
    if capability.startswith("plugin.") or capability.startswith("framework."):
        return "C001-C099"
    return "C900-C999"


def format_event_time(event: Event) -> str:
    """Return a user-facing timestamp with timezone."""
    return format_operator_timestamp(event.created_at)


def format_capability_inventory(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width capability inventory table."""
    columns = ["Capability", "Range", "Declared By", "Last Used", "Last User", "Missing", "Status"]
    widths = {
        column: max(len(column), *(len(row[column]) for row in rows)) if rows else len(column)
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    ruler = "  ".join("-" * widths[column] for column in columns)
    body = ["  ".join(row[column].ljust(widths[column]) for column in columns) for row in rows]
    return "\n".join([header, ruler, *body])
