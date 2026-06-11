"""Manifest graph data model.

Constructed by: `bywaf.registry.graph.build_manifest_graph()`.
Used by: registry dependency validation, plugin graph display, plugin-check
graph output, and tests that inspect manifest-only relationships.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ManifestGraphNode:
    """One plugin/provider node derived from manifest metadata.

    Manifest graph construction creates one node per provider before importing
    plugin Python. Registry tooling, dependency checks, and graph renderers
    consume it to reason about schemas, topics, capabilities, variables, roles,
    and explicit plugin dependencies.
    """

    provider: str
    commandlets: tuple[str, ...]
    requires_bywaf: str | None
    requires_schemas: tuple[str, ...]
    requires_plugins: tuple[str, ...]
    schemas: tuple[str, ...]
    consumes: tuple[str, ...]
    emits: tuple[str, ...]
    capabilities: tuple[str, ...]
    database_reads: tuple[str, ...]
    database_writes: tuple[str, ...]
    triggers: tuple[str, ...]
    trigger_topics: tuple[str, ...]
    trigger_actions: tuple[str, ...]
    provider_variables: tuple[str, ...]
    secret_provider_variables: tuple[str, ...]
    secret_options: tuple[str, ...]
    traits: tuple[str, ...]
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManifestRelationship:
    """One manifest-derived graph edge.

    `build_manifest_graph` emits these edges for explicit dependencies and
    inferred relationships such as provided schemas, consumed/emitted topics,
    trigger topics, and commandlets. Graph queries and renderers consume them.
    """

    source: str
    kind: str
    target: str
    hard: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ManifestRelationshipGraph:
    """Provider nodes and manifest-derived relationship edges.

    Registry and tool code build this graph from manifests without loading
    plugin modules. Dependency resolution, schema/topic audits, and graph output
    consume its lookup indexes.
    """

    nodes: dict[str, ManifestGraphNode]
    edges: tuple[ManifestRelationship, ...]
    schema_providers: dict[str, tuple[str, ...]] = field(init=False)
    topic_producers: dict[str, tuple[str, ...]] = field(init=False)
    topic_consumers: dict[str, tuple[str, ...]] = field(init=False)
    commandlet_providers: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        """Build lookup indexes for common graph questions."""
        object.__setattr__(self, "schema_providers", tuple_map(self.edges, "provides_schema"))
        object.__setattr__(self, "topic_producers", tuple_map(self.edges, "emits_topic"))
        object.__setattr__(self, "topic_consumers", tuple_map(self.edges, "consumes_topic"))
        commandlet_providers = {}
        for edge in self.edges:
            if edge.kind == "provides_commandlet":
                commandlet_providers[edge.target] = edge.source
        object.__setattr__(self, "commandlet_providers", commandlet_providers)

    def providers_for_schema(self, topic: str) -> tuple[str, ...]:
        """Return providers that own a schema for one topic."""
        return self.schema_providers.get(topic, ())

    def producers_for_topic(self, topic: str) -> tuple[str, ...]:
        """Return providers that declare they may emit one topic."""
        return self.topic_producers.get(topic, ())

    def consumers_for_topic(self, topic: str) -> tuple[str, ...]:
        """Return providers that declare they may consume one topic."""
        return self.topic_consumers.get(topic, ())

    def provider_for_commandlet(self, commandlet: str) -> str | None:
        """Return the manifest provider for one commandlet, if unique."""
        return self.commandlet_providers.get(commandlet)

    def relationships_for(self, provider: str) -> tuple[ManifestRelationship, ...]:
        """Return all relationships with the provider as source."""
        return tuple(edge for edge in self.edges if edge.source == provider)

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-serializable representation."""
        return {
            "providers": {provider: node_to_dict(node) for provider, node in sorted(self.nodes.items())},
            "edges": [edge_to_dict(edge) for edge in self.edges],
            "schema_providers": self.schema_providers,
            "topic_producers": self.topic_producers,
            "topic_consumers": self.topic_consumers,
            "commandlet_providers": self.commandlet_providers,
        }


def node_to_dict(node: ManifestGraphNode) -> dict[str, object]:
    """Return a JSON-serializable node mapping."""
    return {
        "provider": node.provider,
        "commandlets": node.commandlets,
        "requires_bywaf": node.requires_bywaf,
        "requires_schemas": node.requires_schemas,
        "requires_plugins": node.requires_plugins,
        "schemas": node.schemas,
        "consumes": node.consumes,
        "emits": node.emits,
        "capabilities": node.capabilities,
        "database_reads": node.database_reads,
        "database_writes": node.database_writes,
        "triggers": node.triggers,
        "trigger_topics": node.trigger_topics,
        "trigger_actions": node.trigger_actions,
        "provider_variables": node.provider_variables,
        "secret_provider_variables": node.secret_provider_variables,
        "secret_options": node.secret_options,
        "traits": node.traits,
        "roles": node.roles,
    }


def edge_to_dict(edge: ManifestRelationship) -> dict[str, object]:
    """Return a JSON-serializable edge mapping."""
    return {
        "source": edge.source,
        "kind": edge.kind,
        "target": edge.target,
        "hard": edge.hard,
        "detail": edge.detail,
    }


def tuple_map(edges: tuple[ManifestRelationship, ...], kind: str) -> dict[str, tuple[str, ...]]:
    """Return target-to-source tuple map for one relationship kind."""
    mapping: dict[str, list[str]] = {}
    for edge in edges:
        if edge.kind == kind:
            mapping.setdefault(edge.target, []).append(edge.source)
    return {target: tuple(sorted(sources)) for target, sources in sorted(mapping.items())}
