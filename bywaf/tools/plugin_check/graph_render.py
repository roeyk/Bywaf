"""Graph rendering helpers for plugin checker reports.

Used by:
- `plugin_check` diagnostics, LLM feedback output, CI checks, and external
  plugin author workflows.
- tests that lock down plugin authoring contracts.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def format_collection_graph_summary(graph: dict[str, Any]) -> list[str]:
    """Return compact graph lines for a plugin collection."""
    providers = graph.get("providers") or {}
    edges = graph.get("edges") or []
    schema_providers = graph.get("schema_providers") or {}
    topic_producers = graph.get("topic_producers") or {}
    return [
        f"relationship graph: providers={len(providers)} edges={len(edges)} "
        f"schemas={len(schema_providers)} produced_topics={len(topic_producers)}",
    ]


def format_single_graph_summary(graph: dict[str, Any]) -> list[str]:
    """Return compact graph lines for one plugin."""
    lines = [f"relationship graph: provider={graph.get('provider', '')}"]
    simple_rows = (
        ("requires schemas", graph.get("requires_schemas") or ()),
        ("requires plugins", graph.get("requires_plugins") or ()),
        ("schemas", graph.get("schemas") or ()),
        ("capabilities", graph.get("capabilities") or ()),
        ("database reads", graph.get("database_reads") or ()),
        ("database writes", graph.get("database_writes") or ()),
    )
    for label, values in simple_rows:
        if values:
            lines.append(f"  {label}: {comma_join(values)}")
    for item in graph.get("consumes") or ():
        lines.append("  consumes: " + format_topic_context(item, include_consumers=False))
    for item in graph.get("emits") or ():
        lines.append("  emits: " + format_topic_context(item, include_consumers=True))
    return lines


def llm_relationship_feedback(graph: dict[str, Any]) -> list[str]:
    """Return LLM-oriented relationship context."""
    lines = ["", "Manifest relationship context:"]
    for schema in graph.get("requires_schemas") or ():
        lines.append(f"- requires schema {schema}")
    for provider in graph.get("requires_plugins") or ():
        lines.append(f"- requires plugin {provider}")
    for item in graph.get("consumes") or ():
        lines.append(f"- consumes {format_topic_context(item, include_consumers=False)}")
    for item in graph.get("emits") or ():
        lines.append(f"- emits {format_topic_context(item, include_consumers=True)}")
    if not (graph.get("consumes") or graph.get("emits")):
        lines.append("- no manifest consumes/emits relationships declared")
    lines.append("Use this as advisory context; consumes does not automatically load dependency plugins.")
    return lines


def format_topic_context(item: dict[str, Any], *, include_consumers: bool) -> str:
    """Return one compact topic relationship line."""
    parts = [str(item.get("topic", "")), f"schema={item.get('schema_status', '')}"]
    schema_providers = item.get("schema_providers") or ()
    producers = item.get("known_producers") or ()
    consumers = item.get("known_consumers") or ()
    if schema_providers:
        parts.append("schema_providers=" + comma_join(schema_providers))
    if producers:
        parts.append("producers=" + comma_join(producers))
    if include_consumers and consumers:
        parts.append("consumers=" + comma_join(consumers))
    return " ".join(parts)


def comma_join(values: Sequence[object]) -> str:
    """Return comma-separated text for simple value lists."""
    return ", ".join(str(item) for item in values)
