"""Manifest-derived plugin dependency and relationship graph.

Builds a pre-import graph from plugin manifests. The graph separates hard
metadata that is already supported, such as `requires_bywaf`, from advisory
relationships inferred from consumes/emits, schemas, capabilities, triggers,
variables, and traits.

Used by:
- registry and plugin tooling: reason about plugin relationships without
  importing plugin Python.
- future dependency resolution: order explicit dependencies before dependents."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .config import parse_package_plugin_config
from .manifest import PluginManifest, load_package_manifest


@dataclass(frozen=True, slots=True)
class ManifestGraphNode:
    """One plugin/provider node derived from manifest metadata."""

    provider: str
    commandlets: tuple[str, ...]
    requires_bywaf: str | None
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
    """One manifest-derived graph edge."""

    source: str
    kind: str
    target: str
    hard: bool = False
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ManifestRelationshipGraph:
    """Provider nodes and manifest-derived relationship edges."""

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


def build_package_manifest_graph(
    package_name: str = "bywaf.plugins",
    config_name: str = "plugins.toml",
) -> ManifestRelationshipGraph:
    """Build a graph for bundled plugin manifests without importing plugins."""
    manifests = {}
    for entry in parse_package_plugin_config(package_name, config_name):
        manifest = load_package_manifest(package_name, entry)
        if manifest is not None:
            manifests[entry] = manifest
    return build_manifest_graph(manifests)


def build_manifest_graph(manifests: dict[str, PluginManifest]) -> ManifestRelationshipGraph:
    """Build a graph from provider path to parsed manifest metadata."""
    nodes = {provider: node_from_manifest(provider, manifest) for provider, manifest in manifests.items()}
    edges = []
    for provider, node in nodes.items():
        edges.extend(relationships_from_node(provider, node))
    return ManifestRelationshipGraph(nodes=nodes, edges=tuple(sorted(edges, key=edge_key)))


def node_from_manifest(provider: str, manifest: PluginManifest) -> ManifestGraphNode:
    """Return one graph node from a parsed manifest."""
    capabilities = sorted_set(flatten(manifest.commandlet_capabilities.values()))
    return ManifestGraphNode(
        provider=provider,
        commandlets=tuple(sorted(manifest.commandlets)),
        requires_bywaf=manifest.requires_bywaf,
        schemas=tuple(sorted(schema.topic for schema in manifest.event_schemas)),
        consumes=tuple(sorted_set(flatten(manifest.commandlet_consumes.values()))),
        emits=tuple(sorted_set(flatten(manifest.commandlet_emits.values()))),
        capabilities=tuple(capabilities),
        database_reads=tuple(db_topics(capabilities, "db.read:")),
        database_writes=tuple(db_topics(capabilities, "db.write:")),
        triggers=tuple(sorted(trigger.name for trigger in manifest.triggers)),
        trigger_topics=tuple(sorted_set(trigger.topic for trigger in manifest.triggers)),
        trigger_actions=tuple(sorted_set(trigger.action_command for trigger in manifest.triggers)),
        provider_variables=tuple(sorted_set(flatten(manifest.commandlet_provider_variables.values()))),
        secret_provider_variables=tuple(sorted_set(flatten(manifest.commandlet_secret_provider_variables.values()))),
        secret_options=tuple(sorted_set(flatten(manifest.commandlet_secret_options.values()))),
        traits=traits_from_manifest(manifest),
        roles=tuple(sorted(manifest.roles)),
    )


def relationships_from_node(provider: str, node: ManifestGraphNode) -> list[ManifestRelationship]:
    """Return graph edges derived from one node."""
    edges: list[ManifestRelationship] = []
    if node.requires_bywaf is not None:
        edges.append(ManifestRelationship(provider, "requires_bywaf", node.requires_bywaf, hard=True))
    for kind, values in relationship_groups(node):
        edges.extend(ManifestRelationship(provider, kind, value) for value in values)
    return edges


def relationship_groups(node: ManifestGraphNode) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return relationship labels and values for one graph node."""
    return (
        ("provides_commandlet", node.commandlets),
        ("provides_schema", node.schemas),
        ("consumes_topic", node.consumes),
        ("emits_topic", node.emits),
        ("uses_capability", node.capabilities),
        ("reads_topic", node.database_reads),
        ("writes_topic", node.database_writes),
        ("provides_trigger", node.triggers),
        ("trigger_watches_topic", node.trigger_topics),
        ("trigger_runs_command", node.trigger_actions),
        ("uses_provider_variable", node.provider_variables),
        ("uses_secret_provider_variable", node.secret_provider_variables),
        ("uses_secret_option", node.secret_options),
        ("has_trait", node.traits),
        ("has_role", node.roles),
    )


def traits_from_manifest(manifest: PluginManifest) -> tuple[str, ...]:
    """Return implementation traits from plugin table booleans."""
    traits = []
    if manifest.native:
        traits.append("native")
    if manifest.library_backed:
        traits.append("library_backed")
    if manifest.process_wrapped:
        traits.append("process_wrapped")
    if manifest.service:
        traits.append("service")
    return tuple(sorted(traits))


def db_topics(capabilities: list[str], prefix: str) -> list[str]:
    """Return database capability topics for one capability prefix."""
    return sorted(capability.removeprefix(prefix) for capability in capabilities if capability.startswith(prefix))


def flatten(values: Iterable[Iterable[str]]) -> list[str]:
    """Return a flat list from nested string iterables."""
    flattened = []
    for value in values:
        flattened.extend(value)
    return flattened


def sorted_set(values: Iterable[str]) -> list[str]:
    """Return sorted unique string values."""
    return sorted(set(values))


def tuple_map(edges: tuple[ManifestRelationship, ...], kind: str) -> dict[str, tuple[str, ...]]:
    """Return target-to-source tuple map for one relationship kind."""
    mapping: dict[str, list[str]] = {}
    for edge in edges:
        if edge.kind == kind:
            mapping.setdefault(edge.target, []).append(edge.source)
    return {target: tuple(sorted(sources)) for target, sources in sorted(mapping.items())}


def edge_key(edge: ManifestRelationship) -> tuple[str, str, str, str]:
    """Return stable sort key for relationships."""
    return (edge.source, edge.kind, edge.target, edge.detail)
