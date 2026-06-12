"""Plugin relationship graph display helpers.

Called by: `bywaf.repl.display.catalog.print_plugin_graph()` compatibility
import when an operator asks for plugin/schema dependency graph output.

Used by:
- interactive REPL commands, app-dispatch helpers, and display tests.
- operators who inspect runtime state through built-in commands.
"""

from __future__ import annotations

from collections.abc import Iterable
import json

from ...registry import build_manifest_graph, registered_topics_for_graph, provider_relationship_report
from ...rendering import Column, Table, render_console_table
from ...runner import Runner


def print_plugin_graph(runner: Runner, *, json_output: bool = False, provider: str | None = None, topic: str | None = None) -> None:
    """Print manifest-derived plugin graph relationships.

    Called by: the REPL catalog display command when operators request plugin
    dependency or topic/schema graph output.
    """
    graph = build_manifest_graph(runner.registry.manifests)
    # The command has three report shapes: one provider, one topic, or the full
    # plugin/schema graph plus filesystem auto-load closure.
    if provider:
        # Provider mode is a focused diagnostic: fail early on unknown provider
        # names instead of rendering an empty relationship table that could be
        # mistaken for "known provider with no relationships".
        if provider not in graph.nodes:
            print(f"error: unknown provider {provider}")
            return
        payload = provider_relationship_report(
            graph,
            provider,
            registered_schemas=registered_topics_for_graph(graph),
        )
    elif topic:
        # Topic mode answers "who owns/produces/consumes this data contract?"
        # without requiring the operator to inspect every plugin edge.
        payload = {
            "topic": topic,
            "schema_providers": graph.providers_for_schema(topic),
            "producers": graph.producers_for_topic(topic),
            "consumers": graph.consumers_for_topic(topic),
        }
    else:
        payload = graph.to_dict()
        payload["filesystem_dependency_closure"] = fs_dep_closure_payload(runner)
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(render_plugin_graph_payload(runner, payload))


def render_plugin_graph_payload(runner: Runner, payload: dict[str, object]) -> str:
    """Return a human-readable plugin graph report.

    Called by: `print_plugin_graph()` after it builds the JSON-compatible graph
    payload. The same payload shapes are used for both `--json` and text output,
    so this function routes by keys already present in the payload.
    """
    # Dispatch on payload shape rather than an external mode enum because JSON
    # output and text output are both built from the same graph payloads.
    if "providers" in payload:
        return render_full_plugin_graph(runner, payload)
    if "topic" in payload:
        # Topic payloads are intentionally a single-row table. This keeps schema
        # ownership, producers, and consumers visually adjacent for one topic.
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


def render_full_plugin_graph(runner: Runner, payload: dict[str, object]) -> str:
    """Return default human-readable plugin and schema graph sections.

    Used by: full `plugins graph` display, where operators need both the
    filesystem auto-load closure and manifest relationship graph in one report.
    """
    edges = payload.get("edges")
    edge_rows = edges if isinstance(edges, list) else []
    # Split the manifest graph into operator-facing sections so plugin
    # dependencies and topic/schema relationships do not blur together.
    # `requires_plugin` is a load-order relationship; schema/topic edges are
    # data-contract relationships and should not imply auto-loading by name.
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
    closure_rows = fs_dep_rows(closure)
    # Section 1: show the resolved local-filesystem plugin load order. This is
    # the apt-like dependency closure the registry computed before loading.
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
    # Section 2: show only hard plugin-to-plugin requirements declared as
    # `requires_plugins`, separate from schema/topic data contracts.
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
    # Section 3: show schema ownership and topic production/consumption edges.
    # These are data-contract relationships, not automatic plugin load edges.
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


def fs_dep_closure_payload(runner: Runner) -> dict[str, object]:
    """Return configured and auto-loaded filesystem plugin closure metadata.

    Called by: `print_plugin_graph()` for the full graph payload. The registry
    populates these fields while resolving local filesystem plugin dependencies.
    """
    registry = runner.registry
    return {
        "requested": list(registry.filesystem_requested_providers),
        "auto_loaded": list(registry.fs_autoloaded_providers),
        "load_order": list(registry.filesystem_load_order),
        "auto_load_reasons": dict(registry.filesystem_auto_load_reasons),
    }


def fs_dep_rows(closure: object) -> list[dict[str, str]]:
    """Return display rows for filesystem dependency closure metadata.

    Used by: `render_full_plugin_graph()` to turn registry load metadata into a
    stable table. Invalid or absent closure payloads intentionally render as no
    rows instead of raising in the operator-facing display path.
    """
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
        # Classify how each filesystem plugin entered the load order: requested
        # by config, auto-loaded as a dependency, or loaded by another path.
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
    """Return a table for one provider graph report.

    Used by: `plugins graph provider=<name>` text output. The provider payload
    is produced by `provider_relationship_report()` and contains both scalar
    manifest fields and expanded topic context rows.
    """
    rows = []
    # Scalar manifest fields are shown first, followed by expanded consume/emit
    # topic context that includes known producers, consumers, and schema owners.
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
            # Consumes rows show upstream context. Consumer context is omitted
            # here because this provider is itself the consumer.
            rows.append({"relationship": "consumes", "values": topic_context_text(item, include_consumers=False)})
    for item in object_sequence(payload.get("emits")):
        if isinstance(item, dict):
            # Emits rows include downstream consumers so authors can see who may
            # be affected by a topic payload or schema change.
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
    """Return compact text for one topic relationship.

    Called by: `render_provider_graph_payload()` for consumed and emitted
    topics. Emitted topics include consumer context; consumed topics omit it to
    keep the provider row focused on the upstream data source.
    """
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
    """Return comma-separated display text for a sequence-like value.

    Used by: every graph renderer that collapses list-like manifest fields into
    a single table cell.
    """
    if not values:
        return "-"
    if isinstance(values, (str, bytes)):
        return str(values)
    return ", ".join(str(value) for value in object_sequence(values))


def object_sequence(values: object) -> Iterable[object]:
    """Return an iterable view for display payload sequence fields.

    Used by: graph display helpers before iterating optional payload fields.
    Strings are treated as scalar values, not sequences of characters.
    """
    if values is None or isinstance(values, (str, bytes)):
        return ()
    if isinstance(values, Iterable):
        return values
    return ()
