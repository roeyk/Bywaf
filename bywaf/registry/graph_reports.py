"""Compatibility facade for manifest graph report helpers.

Used by:
- plugin registry loading, manifest validation, plugin graph display, and
  plugin-check diagnostics.
- tests that assert manifest and dependency behavior.
"""

from __future__ import annotations

from .graph.reports import (
    registered_topics_for_graph,
    provider_relationship_report,
    schema_status,
    topic_context,
)

__all__ = [
    "registered_topics_for_graph",
    "provider_relationship_report",
    "schema_status",
    "topic_context",
]
