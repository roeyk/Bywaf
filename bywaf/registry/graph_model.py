"""Compatibility facade for manifest graph data models.

Used by:
- plugin registry loading, manifest validation, plugin graph display, and
  plugin-check diagnostics.
- tests that assert manifest and dependency behavior.
"""

from __future__ import annotations

from .graph.model import (
    ManifestGraphNode,
    ManifestRelationship,
    ManifestRelationshipGraph,
    edge_to_dict,
    node_to_dict,
    tuple_map,
)

__all__ = [
    "ManifestGraphNode",
    "ManifestRelationship",
    "ManifestRelationshipGraph",
    "edge_to_dict",
    "node_to_dict",
    "tuple_map",
]
