"""Rendering helpers for plugin checker reports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .graph_render import (
    format_collection_graph_summary,
    format_single_graph_summary,
)
from .llm_render import render_llm_feedback as render_llm_feedback

def render_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output."""
    if "plugins" in report:
        return render_plugin_collection_text(report)
    return render_single_plugin_text(report)


def render_plugin_collection_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output for a plugin collection."""
    failed = [item for item in report["plugins"] if not item["ok"]]
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']} checked={report['checked']} failed={len(failed)}"]
    if report.get("relationship_graph"):
        lines.extend(format_collection_graph_summary(report["relationship_graph"]))
    for item in report["plugins"]:
        status = "ok" if item["ok"] else "failed"
        commandlets = ", ".join(str(commandlet) for commandlet in item.get("commandlets", ()))
        lines.append(f"{status} entry={item['entry']} commandlets={commandlets}")
        for error in item.get("errors", ()):
            lines.append(f"  error: {error}")
    return "\n".join(lines)


def render_single_plugin_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output for one plugin."""
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']}"]
    commandlets = list_field(report, "commandlets")
    triggers = list_field(report, "triggers")
    errors = list_field(report, "errors")
    missing_capabilities = list_field(report, "missing_capabilities")
    missing_shared_emits = list_field(report, "missing_shared_emits")
    unregistered_declared_emits = list_field(report, "unregistered_declared_emits")
    unused_capabilities = list_field(report, "unused_capabilities")
    inferred_capabilities = list_field(report, "inferred_capabilities")
    inferred_emits = list_field(report, "inferred_emits")
    capability_codes = dict_field(report, "capability_codes")
    warnings = list_field(report, "warnings")
    diagnostics = list_field(report, "diagnostics")
    relationship_graph = dict_field(report, "relationship_graph")
    if commandlets:
        lines.append("commandlets: " + ", ".join(str(item) for item in commandlets))
    append_optional_text_rows(
        lines,
        report=report,
        triggers=triggers,
        inferred_capabilities=inferred_capabilities,
        capability_codes=capability_codes,
        inferred_emits=inferred_emits,
        missing_capabilities=missing_capabilities,
        missing_shared_emits=missing_shared_emits,
        unregistered_declared_emits=unregistered_declared_emits,
        unused_capabilities=unused_capabilities,
    )
    lines.extend(format_text_warning(warning) for warning in warnings)
    lines.extend(format_text_diagnostic(diagnostic) for diagnostic in diagnostics)
    if relationship_graph:
        lines.extend(format_single_graph_summary(relationship_graph))
    for error in errors:
        lines.append(f"error: {error}")
    return "\n".join(lines)


def list_field(report: dict[str, Any], key: str) -> list[Any]:
    """Return one report field as a list for renderer loops.

    Called by: `render_single_plugin_text()`.
    """

    value = report.get(key)
    return value if isinstance(value, list) else []


def dict_field(report: dict[str, Any], key: str) -> dict[str, Any]:
    """Return one report field as a dict for renderer lookups.

    Called by: `render_single_plugin_text()`.
    """

    value = report.get(key)
    return value if isinstance(value, dict) else {}


def append_optional_text_rows(
    lines: list[str],
    *,
    report: dict[str, Any],
    triggers: list[object],
    inferred_capabilities: list[str],
    capability_codes: dict[str, Any],
    inferred_emits: list[str],
    missing_capabilities: list[str],
    missing_shared_emits: list[str],
    unregistered_declared_emits: list[str],
    unused_capabilities: list[str],
) -> None:
    """Append optional single-plugin text sections."""
    optional_rows = (
        ("plugin_version", "plugin version: {value}"),
        ("requires_bywaf", "requires Bywaf: {value}"),
    )
    for key, template in optional_rows:
        if report.get(key):
            lines.append(template.format(value=report[key]))
    sequence_rows = (
        ("triggers", triggers, lambda values: ", ".join(str(item) for item in values)),
        ("inferred capabilities", inferred_capabilities, comma_join),
        ("capability codes", list(capability_codes), lambda _values: format_capability_codes(capability_codes)),
        ("inferred emits", inferred_emits, comma_join),
        ("missing inferred capabilities", missing_capabilities, comma_join),
        ("missing shared event emits declarations", missing_shared_emits, comma_join),
        ("unregistered declared emits", unregistered_declared_emits, comma_join),
        ("unused declared capabilities", unused_capabilities, comma_join),
    )
    for label, values, formatter in sequence_rows:
        if values:
            lines.append(f"{label}: {formatter(values)}")


def comma_join(values: Sequence[object]) -> str:
    """Return comma-separated text for simple value lists."""
    return ", ".join(str(item) for item in values)


def format_text_warning(warning: dict[str, Any]) -> str:
    """Return one plain-text checker warning row."""
    return (
        "warning: "
        f"{warning['capability']} {warning['kind']} "
        f"{warning['path']}:{warning['line']} {warning['detail']}"
    )


def format_text_diagnostic(diagnostic: dict[str, Any]) -> str:
    """Return one plain-text checker diagnostic row."""
    return (
        f"{diagnostic['severity']}: {diagnostic['code']} "
        f"{diagnostic['path']}:{diagnostic['line']} {diagnostic['message']}"
    )


def format_capability_codes(capability_codes: dict[str, Any]) -> str:
    """Return compact capability-to-code display text."""
    return ", ".join(f"{capability}={code}" for capability, code in sorted(capability_codes.items()))
