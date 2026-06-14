"""Manifest-derived plugin dependency and relationship graph.

Builds a pre-import graph from plugin manifests. The graph separates hard
metadata that is already supported, such as `requires_bywaf`, from advisory
relationships inferred from consumes/emits, schemas, capabilities, triggers,
variables, and traits.

Used by:
- registry and plugin tooling: reason about plugin relationships without
  importing plugin Python.
- future dependency resolution: order explicit dependencies before dependents.

Public surface: re-exports graph models, graph builders, dependency validators,
and report helpers from the focused implementation modules.
"""

from __future__ import annotations

from .builder import build_manifest_graph as build_manifest_graph
from .builder import build_package_manifest_graph as build_package_manifest_graph
from .builder import bundled_manifest_map as bundled_manifest_map
from .builder import dependency_errors as dependency_errors
from .builder import provider_in_graph as provider_in_graph
from .builder import validate_manifest_dependencies as validate_manifest_dependencies
from .model import ManifestGraphNode as ManifestGraphNode
from .model import ManifestRelationship as ManifestRelationship
from .model import ManifestRelationshipGraph as ManifestRelationshipGraph
from .reports import provider_relationship_report as provider_relationship_report
from .reports import registered_topics_for_graph as registered_topics_for_graph

__all__ = [
    "ManifestGraphNode",
    "ManifestRelationship",
    "ManifestRelationshipGraph",
    "build_manifest_graph",
    "build_package_manifest_graph",
    "bundled_manifest_map",
    "dependency_errors",
    "provider_in_graph",
    "registered_topics_for_graph",
    "provider_relationship_report",
    "validate_manifest_dependencies",
]
