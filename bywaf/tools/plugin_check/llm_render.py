"""LLM-oriented rendering for plugin checker reports.

Used by:
- `plugin_check` diagnostics, LLM feedback output, CI checks, and external
  plugin author workflows.
- tests that lock down plugin authoring contracts.
"""

from __future__ import annotations

from typing import Any

from .graph_render import format_collection_graph_summary, llm_relationship_feedback


def render_llm_feedback(report: dict[str, Any]) -> str:
    """Return concise feedback suitable for pasting into an LLM chat.

    Called by: `scripts/plugin_check.py` when `--llm-feedback` is requested.
    """

    if "plugins" in report:
        # Collection reports summarize many plugins; detailed remediation is
        # only useful for single-plugin authoring loops.
        return render_collection_feedback(report)
    lines = [f"{'PASSED' if report['ok'] else 'FAILED'}: Bywaf plugin check", f"Plugin: {report['plugin']}"]
    # Pull report sections into local names so the main renderer reads in the
    # same order as the final feedback output.
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
            # Even clean plugins may need graph context when the prompt asks an
            # external LLM to reason about schemas, dependencies, or consumers.
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


def render_collection_feedback(report: dict[str, Any]) -> str:
    """Return collection feedback without importing the human text renderer.

    Called by: `render_llm_feedback()` for `--all`/collection reports.
    """

    failed = [item for item in report["plugins"] if not item["ok"]]
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']} checked={report['checked']} failed={len(failed)}"]
    if report.get("relationship_graph"):
        lines.extend(format_collection_graph_summary(report["relationship_graph"]))
    for item in report["plugins"]:
        # Keep collection feedback intentionally terse; the user can rerun the
        # checker on one failing plugin to get numbered remediation steps.
        status = "ok" if item["ok"] else "failed"
        commandlets = ", ".join(str(commandlet) for commandlet in item.get("commandlets", ()))
        lines.append(f"{status} entry={item['entry']} commandlets={commandlets}")
        for error in item.get("errors", ()):
            lines.append(f"  error: {error}")
    return "\n".join(lines)


def has_llm_feedback(*items: object) -> bool:
    """Return whether a checker report has any LLM feedback item.

    Called by: `render_llm_feedback()`.
    """

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
    """Append numbered LLM feedback items in stable checker priority order.

    Called by: `render_llm_feedback()`.
    """

    item_number = 1
    # Diagnostics come first because they are precise source-authoring issues
    # with line numbers and tailored guidance.
    for diagnostic in diagnostics:
        lines.extend(llm_diagnostic_feedback(item_number, diagnostic))
        item_number += 1
    # Capability and topic drift follows diagnostics: these are the most common
    # fix-and-regenerate failures in external LLM plugin submissions.
    for capability in missing_capabilities:
        lines.extend(llm_missing_capability_feedback(item_number, capability, capability_codes))
        item_number += 1
    for warning in warnings:
        lines.extend(llm_warning_feedback(item_number, warning, capability_codes))
        item_number += 1
    for topic in missing_shared_emits:
        lines.extend(llm_missing_emit_feedback(item_number, topic))
        item_number += 1
    for topic in unregistered_declared_emits:
        lines.extend(llm_unreg_emit_feedback(item_number, topic))
        item_number += 1
    for capability in unused_capabilities:
        lines.extend(llm_unused_capability_feedback(item_number, capability, capability_codes))
        item_number += 1
    for error in errors:
        # Suppress raw errors that already have clearer diagnostic-specific
        # guidance above, so the external model gets one instruction per issue.
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
    # Mention both manifest and Python metadata because filesystem plugins are
    # manifest-authoritative, while legacy in-repo examples may still expose
    # CommandSpec/decorator metadata.
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


def llm_missing_emit_feedback(item_number: int, topic: str) -> list[str]:
    """Return LLM feedback lines for one missing shared-event declaration."""
    return [
        f"{item_number}. Missing shared event declaration: {topic}",
        "   Problem: source analysis saw this shared Bywaf event topic being published, but the manifest does not declare it.",
        "   Fix: add the topic to the matching bywaf.plugin.toml [[commandlets]] emits list.",
    ]


def llm_unreg_emit_feedback(item_number: int, topic: str) -> list[str]:
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
        # This is common when an LLM copies only commandlet tables from a
        # skeleton and drops the required [plugin] metadata.
        return [
            f"{item_number}. Missing required manifest field: [plugin].version",
            "   Problem: bywaf.plugin.toml must include a non-empty version string in the [plugin] table.",
            '   Fix: add a line such as version = "0.1.0" under [plugin], or preserve this field when copying a skeleton manifest.',
        ]
    if "does not define plugin()" in error_text:
        # External models frequently decorate plugin() itself or return a class
        # instead of an instance; keep the factory guidance explicit.
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
