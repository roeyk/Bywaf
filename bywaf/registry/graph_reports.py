"""Manifest graph report helpers.

Called by: REPL catalog graph display and plugin-check graph rendering when
they need provider/topic context beyond raw graph nodes and edges.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..event.schemas import event_schema
from .graph_model import ManifestRelationshipGraph, edge_to_dict


def relationship_report_for_provider(
    graph: ManifestRelationshipGraph,
    provider: str,
    *,
    registered_schemas: Iterable[str] = (),
) -> dict[str, object]:
    """Return compact relationship context for one provider."""
    node = graph.nodes[provider]
    registered = set(registered_schemas)
    return {
        "provider": provider,
        "commandlets": node.commandlets,
        "schemas": node.schemas,
        "requires_schemas": node.requires_schemas,
        "requires_plugins": node.requires_plugins,
        "consumes": tuple(
            topic_context(
                topic,
                producers=graph.producers_for_topic(topic),
                consumers=(),
                schema_providers=graph.providers_for_schema(topic),
                registered=topic in registered,
            )
            for topic in node.consumes
        ),
        "emits": tuple(
            topic_context(
                topic,
                producers=graph.producers_for_topic(topic),
                consumers=graph.consumers_for_topic(topic),
                schema_providers=graph.providers_for_schema(topic),
                registered=topic in registered,
            )
            for topic in node.emits
        ),
        "capabilities": node.capabilities,
        "database_reads": node.database_reads,
        "database_writes": node.database_writes,
        "relationships": tuple(edge_to_dict(edge) for edge in graph.relationships_for(provider)),
    }


def registered_topics_for_graph(graph: ManifestRelationshipGraph) -> tuple[str, ...]:
    """Return graph topics with framework/runtime registered schemas."""
    topics = {
        topic
        for node in graph.nodes.values()
        for topic in (*node.schemas, *node.consumes, *node.emits, *node.requires_schemas)
    }
    return tuple(sorted(topic for topic in topics if event_schema(topic) is not None))


def topic_context(
    topic: str,
    *,
    producers: Iterable[str],
    consumers: Iterable[str],
    schema_providers: Iterable[str],
    registered: bool,
) -> dict[str, object]:
    """Return producer/consumer/schema context for one topic."""
    provider_tuple = tuple(sorted(schema_providers))
    return {
        "topic": topic,
        "schema_status": schema_status(provider_tuple, registered=registered),
        "schema_providers": provider_tuple,
        "known_producers": tuple(sorted(producers)),
        "known_consumers": tuple(sorted(consumers)),
    }


def schema_status(schema_providers: tuple[str, ...], *, registered: bool) -> str:
    """Return a compact schema registration label for graph output."""
    if schema_providers:
        return "plugin-owned"
    if registered:
        return "framework-registered"
    return "unregistered"
