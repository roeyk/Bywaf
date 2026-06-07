"""Tests for manifest-derived plugin relationship graphs."""

from bywaf.registry import (
    ManifestRelationship,
    build_package_manifest_graph,
)


def test_bundled_manifest_graph_indexes_schema_providers_without_importing_plugins():
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")

    self_provider = graph.providers_for_schema("http.auth")
    framework_schema_providers = graph.providers_for_schema("http.endpoint")

    assert self_provider == ("http.http_auth",)
    assert framework_schema_providers == ()
    assert graph.provider_for_commandlet("http_auth") == "http.http_auth"


def test_bundled_manifest_graph_separates_consumers_and_producers():
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")

    assert "http.http_auth" in graph.consumers_for_topic("port.open")
    assert "network.portscanner" in graph.producers_for_topic("port.open")
    assert "http.http_auth" in graph.producers_for_topic("http.auth")


def test_bundled_manifest_graph_records_advisory_relationships():
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    relationships = set(graph.relationships_for("http.http_auth"))

    assert ManifestRelationship("http.http_auth", "consumes_topic", "port.open") in relationships
    assert ManifestRelationship("http.http_auth", "emits_topic", "http.auth") in relationships
    assert ManifestRelationship("http.http_auth", "emits_topic", "finding.candidate") in relationships
    assert ManifestRelationship("http.http_auth", "uses_capability", "network.connect") in relationships
    assert ManifestRelationship("http.http_auth", "writes_topic", "http.auth") in relationships
    assert ManifestRelationship("http.http_auth", "writes_topic", "finding.candidate") in relationships
    assert ManifestRelationship("http.http_auth", "has_trait", "native") in relationships
    assert ManifestRelationship("http.http_auth", "has_role", "command-provider") in relationships


def test_bundled_manifest_graph_marks_requires_bywaf_as_hard_edge():
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    hard_edges = [edge for edge in graph.edges if edge.kind == "requires_bywaf"]

    assert all(edge.hard for edge in hard_edges)
