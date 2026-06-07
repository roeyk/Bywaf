#!/usr/bin/env python3
"""Inspect bundled plugin manifest relationships without importing plugins."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bywaf.event.schemas import event_schema  # noqa: E402
from bywaf.registry import build_package_manifest_graph, relationship_report_for_provider  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Build the plugin graph CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_graph.py")
    parser.add_argument("--provider", help="show relationships for one bundled provider entry")
    parser.add_argument("--topic", help="show producers, consumers, and schema providers for one topic")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable graph report")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run bundled manifest graph inspection."""
    args = build_parser().parse_args(argv)
    graph = build_package_manifest_graph("bywaf.plugins", "plugins.toml")
    if args.provider:
        if args.provider not in graph.nodes:
            print(f"error: unknown provider {args.provider}")
            return 1
        report = relationship_report_for_provider(
            graph,
            args.provider,
            registered_schemas=registered_topics_for_graph(graph),
        )
    elif args.topic:
        report = topic_report(graph, args.topic)
    else:
        report = graph.to_dict()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_graph_report(report))
    return 0


def topic_report(graph: Any, topic: str) -> dict[str, object]:
    """Return a compact report for one topic."""
    return {
        "topic": topic,
        "schema_providers": graph.providers_for_schema(topic),
        "producers": graph.producers_for_topic(topic),
        "consumers": graph.consumers_for_topic(topic),
    }


def registered_topics_for_graph(graph: Any) -> tuple[str, ...]:
    """Return graph topics with framework/runtime registered schemas."""
    topics = {
        topic
        for node in graph.nodes.values()
        for topic in (*node.schemas, *node.consumes, *node.emits, *node.requires_schemas)
    }
    return tuple(sorted(topic for topic in topics if event_schema(topic) is not None))


def render_graph_report(report: dict[str, Any]) -> str:
    """Return a compact text graph report."""
    if "providers" in report:
        providers = report.get("providers") or {}
        edges = report.get("edges") or []
        schemas = report.get("schema_providers") or {}
        topics = report.get("topic_producers") or {}
        return (
            f"plugin graph: providers={len(providers)} edges={len(edges)} "
            f"schemas={len(schemas)} produced_topics={len(topics)}"
        )
    if "topic" in report:
        return "\n".join(
            (
                f"topic: {report['topic']}",
                "schema providers: " + comma_join(report.get("schema_providers") or ()),
                "producers: " + comma_join(report.get("producers") or ()),
                "consumers: " + comma_join(report.get("consumers") or ()),
            )
        )
    return "\n".join(provider_report_lines(report))


def provider_report_lines(report: dict[str, Any]) -> list[str]:
    """Return text lines for one provider relationship report."""
    lines = [f"provider: {report['provider']}"]
    for label in (
        "commandlets",
        "requires_schemas",
        "requires_plugins",
        "schemas",
        "capabilities",
        "database_reads",
        "database_writes",
    ):
        values = report.get(label) or ()
        if values:
            lines.append(f"{label.replace('_', ' ')}: {comma_join(values)}")
    for item in report.get("consumes") or ():
        lines.append("consumes: " + topic_context_text(item, include_consumers=False))
    for item in report.get("emits") or ():
        lines.append("emits: " + topic_context_text(item, include_consumers=True))
    return lines


def topic_context_text(item: dict[str, Any], *, include_consumers: bool) -> str:
    """Return compact text for one provider-topic relationship."""
    parts = [str(item.get("topic", "")), f"schema={item.get('schema_status', '')}"]
    producers = item.get("known_producers") or ()
    consumers = item.get("known_consumers") or ()
    if producers:
        parts.append("producers=" + comma_join(producers))
    if include_consumers and consumers:
        parts.append("consumers=" + comma_join(consumers))
    return " ".join(parts)


def comma_join(values: Any) -> str:
    """Return a comma-separated value list or a placeholder."""
    return ", ".join(str(value) for value in values) if values else "-"


if __name__ == "__main__":
    raise SystemExit(main())
