"""Plugin relationship graph display helpers.

Called by: `bywaf.repl.display.catalog.print_plugin_graph()` compatibility
import when an operator asks for plugin/schema dependency graph output.
"""

from __future__ import annotations

from collections.abc import Iterable
import json

from ...registry import build_manifest_graph, registered_topics_for_graph, relationship_report_for_provider
from ...rendering import Column, Table, render_console_table
from ...runner import Runner


def print_plugin_graph(runner: Runner, *, json_output: bool = False, provider: str | None = None, topic: str | None = None) -> None:
    """Print manifest-derived plugin graph relationships."""
    graph = build_manifest_graph(runner.registry.manifests)
    if provider:
        if provider not in graph.nodes:
            print(f"error: unknown provider {provider}")
            return
        payload = relationship_report_for_provider(
            graph,
            provider,
            registered_schemas=registered_topics_for_graph(graph),
        )
    elif topic:
        payload = {
            "topic": topic,
            "schema_providers": graph.providers_for_schema(topic),
            "producers": graph.producers_for_topic(topic),
            "consumers": graph.consumers_for_topic(topic),
        }
    else:
        payload = graph.to_dict()
        payload["filesystem_dependency_closure"] = filesystem_dependency_closure_payload(runner)
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(render_plugin_graph_payload(runner, payload))


def render_plugin_graph_payload(runner: Runner, payload: dict[str, object]) -> str:
    """Return a human-readable plugin graph report."""
    if "providers" in payload:
        return render_full_plugin_graph_payload(runner, payload)
    if "topic" in payload:
        return render_console_table(
            Table(
                (
                    Column("topic", "TOPIC"),
                    Column("schema_providers", "SCHEMA PROVIDERS"),
                    Column("producers", "PRODUCERS"),
                    Column("consumers", "CONSUMERS"),
                ),
                (
                    {
                        "topic": payload.get("topic", ""),
                        "schema_providers": comma_join(payload.get("schema_providers")),
                        "producers": comma_join(payload.get("producers")),
                        "consumers": comma_join(payload.get("consumers")),
                    },
                ),
            ),
            runner.registry.varstore.get,
        )
    return render_provider_graph_payload(runner, payload)


def render_full_plugin_graph_payload(runner: Runner, payload: dict[str, object]) -> str:
    """Return default human-readable plugin and schema graph sections."""
    edges = payload.get("edges")
    edge_rows = edges if isinstance(edges, list) else []
    plugin_rows = [
        {
            "source": str(edge.get("source", "")),
            "target": str(edge.get("target", "")),
        }
        for edge in edge_rows
        if isinstance(edge, dict) and edge.get("kind") == "requires_plugin"
    ]
    schema_rows = [
        {
            "source": str(edge.get("source", "")),
            "kind": schema_edge_label(str(edge.get("kind", ""))),
            "topic": str(edge.get("target", "")),
        }
        for edge in edge_rows
        if isinstance(edge, dict) and edge.get("kind") in {"requires_schema", "provides_schema", "consumes_topic", "emits_topic"}
    ]
    sections = ["Filesystem plugin load closure"]
    closure = payload.get("filesystem_dependency_closure")
    closure_rows = filesystem_dependency_closure_rows(closure)
    if closure_rows:
        sections.append(
            render_console_table(
                Table(
                    (
                        Column("order", "ORDER"),
                        Column("plugin", "PLUGIN"),
                        Column("source", "SOURCE"),
                        Column("reason", "REASON"),
                    ),
                    tuple(closure_rows),
                ),
                runner.registry.varstore.get,
            )
        )
    else:
        sections.append("no filesystem plugin closure loaded")
    sections.append("")
    sections.append("Plugin dependency graph")
    if plugin_rows:
        sections.append(
            render_console_table(
                Table(
                    (
                        Column("source", "PLUGIN"),
                        Column("target", "REQUIRES PLUGIN"),
                    ),
                    tuple(plugin_rows),
                ),
                runner.registry.varstore.get,
            )
        )
    else:
        sections.append("no explicit plugin dependencies")
    sections.append("")
    sections.append("Schema dependency graph")
    if schema_rows:
        sections.append(
            render_console_table(
                Table(
                    (
                        Column("source", "PLUGIN"),
                        Column("kind", "RELATIONSHIP"),
                        Column("topic", "TOPIC"),
                    ),
                    tuple(schema_rows),
                ),
                runner.registry.varstore.get,
            )
        )
    else:
        sections.append("no schema or topic relationships")
    return "\n".join(sections)


def filesystem_dependency_closure_payload(runner: Runner) -> dict[str, object]:
    """Return configured and auto-loaded filesystem plugin closure metadata."""
    registry = runner.registry
    return {
        "requested": list(registry.filesystem_requested_providers),
        "auto_loaded": list(registry.filesystem_auto_loaded_providers),
        "load_order": list(registry.filesystem_load_order),
        "auto_load_reasons": dict(registry.filesystem_auto_load_reasons),
    }


def filesystem_dependency_closure_rows(closure: object) -> list[dict[str, str]]:
    """Return display rows for filesystem dependency closure metadata."""
    if not isinstance(closure, dict):
        return []
    load_order = closure.get("load_order")
    if not isinstance(load_order, list):
        return []
    requested = set(str(provider) for provider in object_sequence(closure.get("requested")))
    auto_loaded = set(str(provider) for provider in object_sequence(closure.get("auto_loaded")))
    reasons = closure.get("auto_load_reasons")
    reason_map = reasons if isinstance(reasons, dict) else {}
    rows = []
    for index, provider in enumerate(load_order, start=1):
        plugin = str(provider)
        if plugin in requested:
            source = "configured"
            reason = "plugin_config"
        elif plugin in auto_loaded:
            source = "auto-loaded"
            reason = str(reason_map.get(plugin, "requires_plugins"))
        else:
            source = "loaded"
            reason = "-"
        rows.append(
            {
                "order": str(index),
                "plugin": plugin,
                "source": source,
                "reason": reason,
            }
        )
    return rows


def schema_edge_label(kind: str) -> str:
    """Return compact display text for schema/topic graph edge kinds."""
    return {
        "requires_schema": "requires",
        "provides_schema": "provides",
        "consumes_topic": "consumes",
        "emits_topic": "emits",
    }.get(kind, kind)


def render_provider_graph_payload(runner: Runner, payload: dict[str, object]) -> str:
    """Return a table for one provider graph report."""
    rows = []
    for label in (
        "commandlets",
        "requires_schemas",
        "requires_plugins",
        "schemas",
        "capabilities",
        "database_reads",
        "database_writes",
    ):
        values = payload.get(label) or ()
        if values:
            rows.append({"relationship": label.replace("_", " "), "values": comma_join(values)})
    for item in object_sequence(payload.get("consumes")):
        if isinstance(item, dict):
            rows.append({"relationship": "consumes", "values": topic_context_text(item, include_consumers=False)})
    for item in object_sequence(payload.get("emits")):
        if isinstance(item, dict):
            rows.append({"relationship": "emits", "values": topic_context_text(item, include_consumers=True)})
    if not rows:
        rows.append({"relationship": "provider", "values": str(payload.get("provider", ""))})
    return render_console_table(
        Table(
            (
                Column("relationship", "RELATIONSHIP"),
                Column("values", "VALUES"),
            ),
            tuple(rows),
            title=str(payload.get("provider", "")) if payload.get("provider") else None,
        ),
        runner.registry.varstore.get,
    )


def topic_context_text(item: dict[str, object], *, include_consumers: bool) -> str:
    """Return compact text for one topic relationship."""
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


def comma_join(values: object) -> str:
    """Return comma-separated display text for a sequence-like value."""
    if not values:
        return "-"
    if isinstance(values, (str, bytes)):
        return str(values)
    return ", ".join(str(value) for value in object_sequence(values))


def object_sequence(values: object) -> Iterable[object]:
    """Return an iterable view for display payload sequence fields."""
    if values is None or isinstance(values, (str, bytes)):
        return ()
    if isinstance(values, Iterable):
        return values
    return ()
