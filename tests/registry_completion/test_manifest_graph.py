"""Tests for manifest-derived plugin relationship graphs.

Coverage focus: registry completion manifest graph regression behavior.
"""

from typing import Any, cast

from bywaf.event.schemas import EventSchema, FieldSchema
from bywaf.registry import (
    ManifestRelationship,
    PluginManifest,
    build_manifest_graph,
    build_package_manifest_graph,
    dependency_errors,
)


def test_bundled_manifest_graph_indexes_schema_providers_without_importing_plugins():
    """Protect bundled manifest graph indexes schema providers without importing plugins behavior from regressions."""
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")

    self_provider = graph.providers_for_schema("http.auth")
    framework_schema_providers = graph.providers_for_schema("http.endpoint")

    assert self_provider == ("http.auth",)
    assert framework_schema_providers == ()
    assert graph.provider_for_commandlet("http_auth") == "http.auth"


def test_bundled_manifest_graph_separates_consumers_and_producers():
    """Protect bundled manifest graph separates consumers and producers behavior from regressions."""
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")

    assert "http.auth" in graph.consumers_for_topic("port.open")
    assert "network.portscanner" in graph.producers_for_topic("port.open")
    assert "http.auth" in graph.producers_for_topic("http.auth")


def test_bundled_manifest_graph_records_advisory_relationships():
    """Protect bundled manifest graph records advisory relationships behavior from regressions."""
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    relationships = set(graph.relationships_for("http.auth"))

    assert ManifestRelationship("http.auth", "consumes_topic", "port.open") in relationships
    assert ManifestRelationship("http.auth", "emits_topic", "http.auth") in relationships
    assert ManifestRelationship("http.auth", "emits_topic", "finding.candidate") in relationships
    assert ManifestRelationship("http.auth", "uses_capability", "network.connect") in relationships
    assert ManifestRelationship("http.auth", "writes_topic", "http.auth") in relationships
    assert ManifestRelationship("http.auth", "writes_topic", "finding.candidate") in relationships
    assert ManifestRelationship("http.auth", "has_trait", "native") in relationships
    assert ManifestRelationship("http.auth", "has_role", "command-provider") in relationships


def test_bundled_manifest_graph_marks_requires_bywaf_as_hard_edge():
    """Protect bundled manifest graph marks requires bywaf as hard edge behavior from regressions."""
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    hard_edges = [edge for edge in graph.edges if edge.kind == "requires_bywaf"]

    assert all(edge.hard for edge in hard_edges)


def test_bundled_manifest_graph_serializes_for_reports():
    """Protect bundled manifest graph serializes for reports behavior from regressions."""
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    data = graph.to_dict()
    providers = cast(dict[str, dict[str, Any]], data["providers"])
    topic_consumers = cast(dict[str, tuple[str, ...]], data["topic_consumers"])
    topic_producers = cast(dict[str, tuple[str, ...]], data["topic_producers"])

    assert providers["http.auth"]["schemas"] == ("http.auth",)
    assert "http.auth" in topic_consumers["port.open"]
    assert "network.portscanner" in topic_producers["port.open"]


def test_manifest_graph_records_explicit_dependency_edges():
    """Protect manifest graph records explicit dependency edges behavior from regressions."""
    manifest = PluginManifest(
        commandlets=frozenset({"consumer"}),
        version="0.1.0",
        requires_schemas=("shared.topic",),
        requires_plugins=("provider.plugin",),
    )
    graph = build_manifest_graph({"consumer.plugin": manifest})
    relationships = set(graph.relationships_for("consumer.plugin"))
    data = graph.to_dict()
    providers = cast(dict[str, dict[str, Any]], data["providers"])

    assert ManifestRelationship("consumer.plugin", "requires_schema", "shared.topic", hard=True) in relationships
    assert ManifestRelationship("consumer.plugin", "requires_plugin", "provider.plugin", hard=True) in relationships
    assert providers["consumer.plugin"]["requires_schemas"] == ("shared.topic",)


def test_dependency_errors_report_ambiguous_schema_providers():
    """Protect dependency errors report ambiguous schema providers behavior from regressions."""
    consumer = PluginManifest(
        commandlets=frozenset({"consumer"}),
        version="0.1.0",
        requires_schemas=("shared.topic",),
    )
    provider_a = schema_provider_manifest("a")
    provider_b = schema_provider_manifest("b")
    graph = build_manifest_graph(
        {
            "consumer.plugin": consumer,
            "provider.a": provider_a,
            "provider.b": provider_b,
        }
    )

    errors = dependency_errors("consumer.plugin", consumer, graph)

    assert errors == ["ambiguous required schema shared.topic: providers provider.a, provider.b"]


def schema_provider_manifest(commandlet: str) -> PluginManifest:
    """Return a manifest that owns the test shared schema."""
    return PluginManifest(
        commandlets=frozenset({commandlet}),
        version="0.1.0",
        event_schemas=(
            EventSchema(
                topic="shared.topic",
                summary="shared test topic",
                fields=(FieldSchema("value", "str"),),
            ),
        ),
    )
