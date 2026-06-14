"""Manifest graph building and dependency validation.

Used by:
- registry loading and filesystem dependency closure: validate hard manifest
  dependencies before importing plugin Python.
- plugin-check and catalog graph output: build manifest-only relationship
  graphs for diagnostics.
"""

from __future__ import annotations

from collections.abc import Iterable

from ...event.schemas import event_schema
from ..config import parse_package_plugin_config
from ..manifest import PluginManifest, load_package_manifest
from .model import ManifestGraphNode, ManifestRelationship, ManifestRelationshipGraph


def build_package_manifest_graph(
    package_name: str = "bywaf.plugins",
    config_name: str = "plugins.toml",
) -> ManifestRelationshipGraph:
    """Build a graph for bundled plugin manifests without importing plugins.

    Called by: plugin graph CLI output, plugin-check graph feedback, and
    registry tests that need manifest relationships without executing provider
    Python.
    """
    manifests = {}
    # The package config lists provider paths. Load only TOML sidecars here so
    # graph construction stays safe for trust previews and dependency checks.
    for entry in parse_package_plugin_config(package_name, config_name):
        manifest = load_package_manifest(package_name, entry)
        if manifest is not None:
            manifests[entry] = manifest
    return build_manifest_graph(manifests)


def bundled_manifest_map(
    package_name: str = "bywaf.plugins",
    config_name: str = "plugins.toml",
) -> dict[str, PluginManifest]:
    """Return bundled manifests keyed by provider path without importing plugins.

    Called by: filesystem dependency closure and bundled registry loading when
    they need a manifest-only view of built-in providers.
    """
    manifests = {}
    for entry in parse_package_plugin_config(package_name, config_name):
        manifest = load_package_manifest(package_name, entry)
        if manifest is not None:
            manifests[entry] = manifest
    return manifests


def build_manifest_graph(manifests: dict[str, PluginManifest]) -> ManifestRelationshipGraph:
    """Build a graph from provider path to parsed manifest metadata.

    Called by: registry dependency validation, filesystem dependency closure,
    plugin-check graph rendering, and tests. This is the central manifest-only
    transformation from parsed TOML to nodes plus typed relationship edges.
    """
    # First normalize each parsed manifest into a node, then derive edges from
    # those nodes. Keeping the phases separate makes it easier for diagnostics
    # to inspect either provider facts or provider relationships.
    nodes = {provider: node_from_manifest(provider, manifest) for provider, manifest in manifests.items()}
    edges = []
    for provider, node in nodes.items():
        edges.extend(relationships_from_node(provider, node))
    return ManifestRelationshipGraph(nodes=nodes, edges=tuple(sorted(edges, key=edge_key)))


def dependency_errors(
    provider: str,
    manifest: PluginManifest,
    graph: ManifestRelationshipGraph,
) -> list[str]:
    """Return manifest hard-dependency diagnostics for one provider.

    Called by: `validate_manifest_dependencies()` and plugin-check paths. Only
    explicit `requires_*` metadata is treated as a hard dependency here;
    consumes/emits edges remain advisory graph context.
    """
    errors = []
    for dependency in manifest.requires_plugins:
        # Plugin dependencies are provider dependencies: if A requires B, B
        # must be available before A can load.
        if dependency == provider:
            errors.append(f"requires_plugins self-dependency: {dependency}")
        elif not provider_in_graph(graph, dependency):
            errors.append(f"missing required plugin: {dependency}")
    for topic in manifest.requires_schemas:
        # Schema dependencies are data-contract dependencies. They may be
        # satisfied by a plugin-owned schema in the graph or by a framework
        # built-in schema registered at runtime.
        providers = graph.providers_for_schema(topic)
        if event_schema(topic) is not None:
            continue
        if not providers:
            errors.append(f"missing required schema: {topic}")
        elif len(providers) > 1:
            errors.append(f"ambiguous required schema {topic}: providers {', '.join(providers)}")
    return errors


def provider_in_graph(graph: ManifestRelationshipGraph, provider: str) -> bool:
    """Return whether a provider exists, accepting dotted or slash notation.

    Called by: hard dependency validation and filesystem dependency closure so
    manifests may use either package-style `http.auth` or path-style
    `http/auth` provider references.
    """
    return provider in graph.nodes or provider.replace("/", ".") in graph.nodes or provider.replace(".", "/") in graph.nodes


def validate_manifest_dependencies(
    manifests: dict[str, PluginManifest],
    *,
    graph: ManifestRelationshipGraph | None = None,
    providers: Iterable[str] | None = None,
) -> None:
    """Reject missing or ambiguous hard manifest dependencies.

    Called by: registry loading, filesystem dependency closure, and plugin
    checking before plugin code is imported. If a dependency chain is incomplete,
    callers fail the whole load/check instead of partially importing providers.
    """
    graph = graph or build_manifest_graph(manifests)
    selected = tuple(providers) if providers is not None else tuple(sorted(manifests))
    errors = []
    for provider in selected:
        manifest = manifests.get(provider)
        if manifest is None:
            continue
        errors.extend(f"{provider}: {error}" for error in dependency_errors(provider, manifest, graph))
    if errors:
        raise ValueError("; ".join(errors))


def node_from_manifest(provider: str, manifest: PluginManifest) -> ManifestGraphNode:
    """Return one graph node from a parsed manifest.

    Called by: `build_manifest_graph()` for each provider. The node captures
    provider facts exactly once so later edge construction and JSON rendering do
    not need to reach back into the raw manifest object.
    """
    capabilities = sorted_set(flatten(manifest.commandlet_capabilities.values()))
    return ManifestGraphNode(
        provider=provider,
        commandlets=tuple(sorted(manifest.commandlets)),
        requires_bywaf=manifest.requires_bywaf,
        requires_schemas=tuple(sorted(manifest.requires_schemas)),
        requires_plugins=tuple(sorted(manifest.requires_plugins)),
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
        secret_provider_variables=tuple(sorted_set(flatten(manifest.commandlet_secret_vars.values()))),
        secret_options=tuple(sorted_set(flatten(manifest.commandlet_secret_options.values()))),
        traits=traits_from_manifest(manifest),
        roles=tuple(sorted(manifest.roles)),
    )


def relationships_from_node(provider: str, node: ManifestGraphNode) -> list[ManifestRelationship]:
    """Return graph edges derived from one node.

    Called by: `build_manifest_graph()`. Hard edges come only from explicit
    requirements; every other edge is advisory context for graph display,
    plugin-check feedback, and future planning.
    """
    edges: list[ManifestRelationship] = []
    if node.requires_bywaf is not None:
        edges.append(ManifestRelationship(provider, "requires_bywaf", node.requires_bywaf, hard=True))
    edges.extend(ManifestRelationship(provider, "requires_schema", topic, hard=True) for topic in node.requires_schemas)
    edges.extend(ManifestRelationship(provider, "requires_plugin", dependency, hard=True) for dependency in node.requires_plugins)
    for kind, values in relationship_groups(node):
        edges.extend(ManifestRelationship(provider, kind, value) for value in values)
    return edges


def relationship_groups(node: ManifestGraphNode) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return relationship labels and values for one graph node.

    Called by: `relationships_from_node()` after hard dependency edges are
    emitted. This tuple is the advisory relationship dispatch table: each label
    maps to the node attribute that should become one edge per value.
    """
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
    """Return implementation traits from plugin table booleans.

    Called by: `node_from_manifest()` so graph output can distinguish native,
    library-backed, process-wrapped, and service providers without importing
    their code.
    """
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
    """Return database capability topics for one capability prefix.

    Called by: `node_from_manifest()` for `db.read:` and `db.write:` capability
    strings before they become graph edges.
    """
    return sorted(capability.removeprefix(prefix) for capability in capabilities if capability.startswith(prefix))


def flatten(values: Iterable[Iterable[str]]) -> list[str]:
    """Return a flat list from nested string iterables.

    Called by: graph node construction for manifest fields stored per
    commandlet, such as consumes, emits, capabilities, and provider variables.
    """
    flattened = []
    for value in values:
        flattened.extend(value)
    return flattened


def sorted_set(values: Iterable[str]) -> list[str]:
    """Return sorted unique string values.

    Called by: graph node construction to keep manifest-derived output stable
    for tests, CLI graph output, and code review diffs.
    """
    return sorted(set(values))


def edge_key(edge: ManifestRelationship) -> tuple[str, str, str, str]:
    """Return stable sort key for relationships.

    Called by: `build_manifest_graph()` before storing edges on the graph so
    rendered graph output and JSON snapshots do not depend on dict iteration.
    """
    return (edge.source, edge.kind, edge.target, edge.detail)
