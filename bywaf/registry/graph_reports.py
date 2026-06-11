"""Compatibility facade for manifest graph report helpers."""

from __future__ import annotations

from .graph.reports import (
    registered_topics_for_graph,
    relationship_report_for_provider,
    schema_status,
    topic_context,
)

__all__ = [
    "registered_topics_for_graph",
    "relationship_report_for_provider",
    "schema_status",
    "topic_context",
]
