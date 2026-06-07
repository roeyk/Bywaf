"""Provider, commandlet, trigger, and topic display helpers.

Provides compact catalog views for loaded providers, commandlets, trigger rules,
and event topics.

Used by:
- repl.commands: implement `plugins`, `cmds`, `triggers`, and `topics`."""

from __future__ import annotations

from collections.abc import Iterable
import json

from ...registry import build_manifest_graph, registered_topics_for_graph, relationship_report_for_provider
from ...pager import page_text
from ...rendering import Column, Table, render_console_table
from ...runner import Runner


def print_topics(runner: Runner, prefix: str = "") -> None:
    """Print event topics known to the active database, optionally filtered."""
    matched = [topic for topic in runner.events.topics() if topic.startswith(prefix)]
    for topic in matched:
        print(topic)
    if prefix and not matched:
        print(f"no matching topics: {prefix}")


def print_plugins(runner: Runner) -> None:
    """Print loaded plugin providers with compact purpose summaries."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        rows.append(
            {
                "provider": provider,
                "count": str(len(commandlets)),
                "description": provider_description(provider, commandlets, runner),
            }
        )
    if rows:
        print(
            render_console_table(
                Table(
                    (
                        Column("provider", "PLUGIN"),
                        Column("count", "CMDS"),
                        Column("description", "WHAT IT DOES"),
                    ),
                    tuple(rows),
                ),
                runner.registry.varstore.get,
            )
        )


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
    sections = ["Plugin dependency graph"]
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


def provider_description(provider: str, commandlets: list[str], runner: Runner) -> str:
    """Return a compact readable provider description."""
    override = provider_descriptions().get(provider)
    if override is not None:
        return override
    if len(commandlets) == 1:
        return runner.registry.plugins[commandlets[0]].spec.description
    return f"{len(commandlets)} commandlets; run `cmds` for command-level details."


def provider_descriptions() -> dict[str, str]:
    """Return concise descriptions for bundled provider groups."""
    return {
        "analysis": "Finding normalization, reporting, and file-analysis helpers.",
        "discovery": "Host and target discovery commandlets.",
        "http": "HTTP probing, fingerprinting, screenshot, and Nikto wrappers.",
        "identity": "Identity and directory-service probes.",
        "network": "Network service discovery and protocol probes.",
        "os": "Local filesystem inspection helpers.",
        "recon": "External and DNS reconnaissance helpers.",
        "runtime": "Core runtime, audit, artifact, bundle, key, and control commands.",
        "storage": "Database storage management.",
        "wireless": "Wireless scanning wrappers.",
    }


def print_commandlets(runner: Runner, *, page: bool = False) -> None:
    """Print commandlets grouped under their plugin providers."""
    lines = render_commandlets(runner)
    if page:
        page_generated_text("\n".join(lines))
        return
    print("\n".join(lines))


def print_triggers(runner: Runner) -> None:
    """Print provider-owned trigger rules."""
    if not runner.registry.triggers:
        print("no triggers loaded")
        return
    states = {str(row["name"]): row for row in runner.db.trigger_states()}
    rows = []
    for trigger in sorted(runner.registry.triggers, key=lambda item: runner.registry.trigger_id(item)):
        trigger_id = runner.registry.trigger_id(trigger)
        state = states.get(trigger_id)
        rows.append(
            {
                "provider": runner.registry.trigger_provider(trigger) or "",
                "name": trigger.name,
                "topic": trigger.topic,
                "action": trigger.action_command,
                "mode": trigger.action_mode,
                "cursor": str(state["last_event_id"]) if state is not None else "0",
            }
        )
    print(
        render_console_table(
            Table(
                (
                    Column("provider", "PROVIDER"),
                    Column("name", "TRIGGER"),
                    Column("topic", "TOPIC"),
                    Column("action", "ACTION"),
                    Column("mode", "MODE"),
                    Column("cursor", "CURSOR"),
                ),
                tuple(rows),
            ),
            runner.registry.varstore.get,
        )
    )


def render_commandlets(runner: Runner) -> list[str]:
    """Return commandlets grouped under their plugin providers as a table."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        for commandlet in commandlets:
            plugin = runner.registry.plugins[commandlet]
            rows.append(
                {
                    "provider": provider,
                    "commandlet": commandlet,
                    "aliases": ", ".join(runner.registry.commandlet_aliases_for(commandlet, include_provider=False)),
                    "description": plugin.spec.description,
                }
            )
    if not rows:
        return []
    return [
        render_console_table(
            Table(
                (
                    Column("provider", "PLUGIN"),
                    Column("commandlet", "COMMANDLET"),
                    Column("aliases", "ALIASES"),
                    Column("description", "WHAT IT DOES"),
                ),
                tuple(rows),
            ),
            runner.registry.varstore.get,
        )
    ]


def page_generated_text(text: str) -> None:
    """Page built-in generated text through the system pager when available."""
    page_text(text)
