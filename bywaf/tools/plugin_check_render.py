"""Rendering helpers for plugin checker reports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .plugin_check_graph_render import (
    format_collection_graph_summary,
    format_single_graph_summary,
    llm_relationship_feedback,
)

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
    commandlets = report.get("commandlets") or []
    triggers = report.get("triggers") or []
    errors = report.get("errors") or []
    missing_capabilities = report.get("missing_capabilities") or []
    missing_shared_emits = report.get("missing_shared_emits") or []
    unregistered_declared_emits = report.get("unregistered_declared_emits") or []
    unused_capabilities = report.get("unused_capabilities") or []
    inferred_capabilities = report.get("inferred_capabilities") or []
    inferred_emits = report.get("inferred_emits") or []
    capability_codes = report.get("capability_codes") or {}
    warnings = report.get("warnings") or []
    diagnostics = report.get("diagnostics") or []
    relationship_graph = report.get("relationship_graph") or {}
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


def render_llm_feedback(report: dict[str, Any]) -> str:
    """Return concise feedback suitable for pasting into an LLM chat."""
    if "plugins" in report:
        return render_text(report)
    lines = [f"{'PASSED' if report['ok'] else 'FAILED'}: Bywaf plugin check", f"Plugin: {report['plugin']}"]
    diagnostics = report.get("diagnostics") or []
    errors = report.get("errors") or []
    warnings = report.get("warnings") or []
    missing_capabilities = report.get("missing_capabilities") or []
    missing_shared_emits = report.get("missing_shared_emits") or []
    unregistered_declared_emits = report.get("unregistered_declared_emits") or []
    unused_capabilities = report.get("unused_capabilities") or []
    relationship_graph = report.get("relationship_graph") or {}
    capability_codes = report.get("capability_codes") or {}
    if not has_llm_feedback(
        diagnostics,
        errors,
        warnings,
        missing_capabilities,
        missing_shared_emits,
        unregistered_declared_emits,
        unused_capabilities,
    ):
        lines.append("No checker feedback.")
        if relationship_graph:
            lines.extend(llm_relationship_feedback(relationship_graph))
        return "\n".join(lines)
    lines.append("")
    if report["ok"]:
        lines.append("Review these notes before regenerating or publishing the plugin:")
    else:
        lines.append("Apply these corrections, then output the complete plugin directory again:")
    extend_llm_feedback_items(
        lines,
        diagnostics=diagnostics,
        missing_capabilities=missing_capabilities,
        warnings=warnings,
        missing_shared_emits=missing_shared_emits,
        unregistered_declared_emits=unregistered_declared_emits,
        unused_capabilities=unused_capabilities,
        errors=errors,
        capability_codes=capability_codes,
    )
    if relationship_graph:
        lines.extend(llm_relationship_feedback(relationship_graph))
    return "\n".join(lines)


def has_llm_feedback(*items: object) -> bool:
    """Return whether a checker report has any LLM feedback item."""
    return any(bool(item) for item in items)


def extend_llm_feedback_items(
    lines: list[str],
    *,
    diagnostics: list[dict[str, Any]],
    missing_capabilities: list[str],
    warnings: list[dict[str, Any]],
    missing_shared_emits: list[str],
    unregistered_declared_emits: list[str],
    unused_capabilities: list[str],
    errors: list[object],
    capability_codes: dict[str, Any],
) -> None:
    """Append numbered LLM feedback items in stable checker priority order."""
    item_number = 1
    for diagnostic in diagnostics:
        lines.extend(llm_diagnostic_feedback(item_number, diagnostic))
        item_number += 1
    for capability in missing_capabilities:
        lines.extend(llm_missing_capability_feedback(item_number, capability, capability_codes))
        item_number += 1
    for warning in warnings:
        lines.extend(llm_warning_feedback(item_number, warning, capability_codes))
        item_number += 1
    for topic in missing_shared_emits:
        lines.extend(llm_missing_shared_emit_feedback(item_number, topic))
        item_number += 1
    for topic in unregistered_declared_emits:
        lines.extend(llm_unregistered_declared_emit_feedback(item_number, topic))
        item_number += 1
    for capability in unused_capabilities:
        lines.extend(llm_unused_capability_feedback(item_number, capability, capability_codes))
        item_number += 1
    for error in errors:
        if any(str(error).startswith(f"{diagnostic['code']}:") for diagnostic in diagnostics):
            continue
        if "does not define plugin()" in str(error) and any(
            diagnostic["code"] == "missing-plugin-factory" for diagnostic in diagnostics
        ):
            continue
        if str(error).startswith("missing shared event emits declarations:"):
            continue
        lines.extend(llm_error_feedback(item_number, error))
        item_number += 1


def llm_diagnostic_feedback(item_number: int, diagnostic: dict[str, Any]) -> list[str]:
    """Return LLM feedback lines for one checker diagnostic."""
    return [
        f"{item_number}. {diagnostic['path']}:{diagnostic['line']} [{diagnostic['code']}]",
        f"   Problem: {diagnostic['message']}",
        f"   Fix: {diagnostic['guidance']}",
    ]


def llm_missing_capability_feedback(item_number: int, capability: str, capability_codes: dict[str, Any]) -> list[str]:
    """Return LLM feedback lines for one missing capability."""
    code_suffix = capability_code_suffix(capability, capability_codes)
    return [
        f"{item_number}. Missing capability declaration: {capability}{code_suffix}",
        "   Problem: source analysis inferred this capability but it is not declared.",
        "   Fix: add the capability to the matching bywaf.plugin.toml [[commandlets]] capabilities list. "
        "For legacy code-only plugins, also keep any Python CommandSpec/@commandlet capability metadata "
        "consistent with the manifest.",
    ]


def llm_warning_feedback(item_number: int, warning: dict[str, Any], capability_codes: dict[str, Any]) -> list[str]:
    """Return LLM feedback lines for one capability warning."""
    capability = str(warning["capability"])
    code_suffix = capability_code_suffix(capability, capability_codes)
    return [
        f"{item_number}. {warning['path']}:{warning['line']} [{warning['kind']}]",
        f"   Problem: direct {capability}{code_suffix} use detected: {warning['detail']}",
        "   Fix: prefer the documented mediated Bywaf context API when one exists, or make sure the "
        "matching capability is declared and the direct API use is intentional.",
    ]


def llm_missing_shared_emit_feedback(item_number: int, topic: str) -> list[str]:
    """Return LLM feedback lines for one missing shared-event declaration."""
    return [
        f"{item_number}. Missing shared event declaration: {topic}",
        "   Problem: source analysis saw this shared Bywaf event topic being published, but the manifest does not declare it.",
        "   Fix: add the topic to the matching bywaf.plugin.toml [[commandlets]] emits list.",
    ]


def llm_unregistered_declared_emit_feedback(item_number: int, topic: str) -> list[str]:
    """Return LLM feedback lines for one declared topic without a registered schema."""
    return [
        f"{item_number}. Unregistered declared event topic: {topic}",
        "   Problem: the manifest declares this topic in emits, but no framework or plugin-owned schema is currently registered for it.",
        "   Fix: add or coordinate a [[event_schemas]] definition when the topic is intended for structured interoperability. "
        "Otherwise keep the declaration and rely on global.topic.unregistered.mode for runtime audit/warn/enforce behavior.",
    ]


def llm_unused_capability_feedback(item_number: int, capability: str, capability_codes: dict[str, Any]) -> list[str]:
    """Return LLM feedback lines for one possibly unused capability."""
    code_suffix = capability_code_suffix(capability, capability_codes)
    return [
        f"{item_number}. Possibly unused declared capability: {capability}{code_suffix}",
        "   Problem: the checker did not infer source evidence for this declaration.",
        "   Fix: remove it if it is unnecessary, or keep it if it is required by runtime behavior the "
        "static checker cannot see.",
    ]


def llm_error_feedback(item_number: int, error: object) -> list[str]:
    """Return LLM feedback lines for one remaining checker error."""
    error_text = str(error)
    if error == "manifest [plugin].version is required":
        return [
            f"{item_number}. Missing required manifest field: [plugin].version",
            "   Problem: bywaf.plugin.toml must include a non-empty version string in the [plugin] table.",
            '   Fix: add a line such as version = "0.1.0" under [plugin], or preserve this field when copying a skeleton manifest.',
        ]
    if "does not define plugin()" in error_text:
        return [
            f"{item_number}. Missing required plugin() factory",
            f"   Problem: {error_text}",
            "   Fix: add an undecorated module-level factory such as `def plugin() -> Commandlet: return your_commandlet`. "
            "For scaffold-generated function commandlets, return the decorated function object and test it through `plugin().run(...)`.",
        ]
    return [
        f"{item_number}. Checker error",
        f"   Problem: {error_text}",
        "   Fix: correct the plugin so scripts/plugin_check.py can import and validate it.",
    ]


def capability_code_suffix(capability: str, capability_codes: dict[str, Any]) -> str:
    """Return formatted capability code suffix when one is available."""
    code = capability_codes.get(capability)
    return f" ({code})" if code else ""


def format_capability_codes(capability_codes: dict[str, Any]) -> str:
    """Return compact capability-to-code display text."""
    return ", ".join(f"{capability}={code}" for capability, code in sorted(capability_codes.items()))
