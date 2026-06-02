"""Rendering helpers for plugin checker reports."""

from __future__ import annotations

from typing import Any


def render_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output."""
    if "plugins" in report:
        failed = [item for item in report["plugins"] if not item["ok"]]
        lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']} checked={report['checked']} failed={len(failed)}"]
        for item in report["plugins"]:
            status = "ok" if item["ok"] else "failed"
            commandlets = ", ".join(str(commandlet) for commandlet in item.get("commandlets", ()))
            lines.append(f"{status} entry={item['entry']} commandlets={commandlets}")
            for error in item.get("errors", ()):
                lines.append(f"  error: {error}")
        return "\n".join(lines)
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']}"]
    commandlets = report.get("commandlets") or []
    triggers = report.get("triggers") or []
    errors = report.get("errors") or []
    missing_capabilities = report.get("missing_capabilities") or []
    missing_shared_emits = report.get("missing_shared_emits") or []
    unused_capabilities = report.get("unused_capabilities") or []
    inferred_capabilities = report.get("inferred_capabilities") or []
    inferred_emits = report.get("inferred_emits") or []
    capability_codes = report.get("capability_codes") or {}
    warnings = report.get("warnings") or []
    diagnostics = report.get("diagnostics") or []
    if commandlets:
        lines.append("commandlets: " + ", ".join(str(item) for item in commandlets))
    if report.get("plugin_version"):
        lines.append(f"plugin version: {report['plugin_version']}")
    if report.get("requires_bywaf"):
        lines.append(f"requires Bywaf: {report['requires_bywaf']}")
    if triggers:
        lines.append("triggers: " + ", ".join(str(item) for item in triggers))
    if inferred_capabilities:
        lines.append("inferred capabilities: " + ", ".join(str(item) for item in inferred_capabilities))
    if capability_codes:
        lines.append("capability codes: " + format_capability_codes(capability_codes))
    if inferred_emits:
        lines.append("inferred emits: " + ", ".join(str(item) for item in inferred_emits))
    if missing_capabilities:
        lines.append("missing inferred capabilities: " + ", ".join(str(item) for item in missing_capabilities))
    if missing_shared_emits:
        lines.append("missing shared event emits declarations: " + ", ".join(str(item) for item in missing_shared_emits))
    if unused_capabilities:
        lines.append("unused declared capabilities: " + ", ".join(str(item) for item in unused_capabilities))
    for warning in warnings:
        lines.append(
            "warning: "
            f"{warning['capability']} {warning['kind']} "
            f"{warning['path']}:{warning['line']} {warning['detail']}"
        )
    for diagnostic in diagnostics:
        lines.append(
            f"{diagnostic['severity']}: {diagnostic['code']} "
            f"{diagnostic['path']}:{diagnostic['line']} {diagnostic['message']}"
        )
    for error in errors:
        lines.append(f"error: {error}")
    return "\n".join(lines)


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
    unused_capabilities = report.get("unused_capabilities") or []
    capability_codes = report.get("capability_codes") or {}
    if not diagnostics and not errors and not warnings and not missing_capabilities and not missing_shared_emits and not unused_capabilities:
        lines.append("No checker feedback.")
        return "\n".join(lines)
    lines.append("")
    if report["ok"]:
        lines.append("Review these notes before regenerating or publishing the plugin:")
    else:
        lines.append("Apply these corrections, then output the complete plugin directory again:")
    item_number = 1
    for diagnostic in diagnostics:
        lines.extend(
            [
                f"{item_number}. {diagnostic['path']}:{diagnostic['line']} [{diagnostic['code']}]",
                f"   Problem: {diagnostic['message']}",
                f"   Fix: {diagnostic['guidance']}",
            ]
        )
        item_number += 1
    for capability in missing_capabilities:
        code = capability_codes.get(capability)
        code_suffix = f" ({code})" if code else ""
        lines.extend(
            [
                f"{item_number}. Missing capability declaration: {capability}{code_suffix}",
                "   Problem: source analysis inferred this capability but it is not declared.",
                "   Fix: add the capability to the matching bywaf.plugin.toml [[commandlets]] capabilities list. "
                "For legacy code-only plugins, also keep any Python CommandSpec/@commandlet capability metadata "
                "consistent with the manifest.",
            ]
        )
        item_number += 1
    for warning in warnings:
        code = capability_codes.get(str(warning["capability"]))
        code_suffix = f" ({code})" if code else ""
        lines.extend(
            [
                f"{item_number}. {warning['path']}:{warning['line']} [{warning['kind']}]",
                f"   Problem: direct {warning['capability']}{code_suffix} use detected: {warning['detail']}",
                "   Fix: prefer the documented mediated Bywaf context API when one exists, or make sure the "
                "matching capability is declared and the direct API use is intentional.",
            ]
        )
        item_number += 1
    for topic in missing_shared_emits:
        lines.extend(
            [
                f"{item_number}. Missing shared event declaration: {topic}",
                "   Problem: source analysis saw this shared Bywaf event topic being published, but the manifest does not declare it.",
                "   Fix: add the topic to the matching bywaf.plugin.toml [[commandlets]] emits list.",
            ]
        )
        item_number += 1
    for capability in unused_capabilities:
        code = capability_codes.get(capability)
        code_suffix = f" ({code})" if code else ""
        lines.extend(
            [
                f"{item_number}. Possibly unused declared capability: {capability}{code_suffix}",
                "   Problem: the checker did not infer source evidence for this declaration.",
                "   Fix: remove it if it is unnecessary, or keep it if it is required by runtime behavior the "
                "static checker cannot see.",
            ]
        )
        item_number += 1
    for error in errors:
        if any(str(error).startswith(f"{diagnostic['code']}:") for diagnostic in diagnostics):
            continue
        if str(error).startswith("missing shared event emits declarations:"):
            continue
        if error == "manifest [plugin].version is required":
            lines.extend(
                [
                    f"{item_number}. Missing required manifest field: [plugin].version",
                    "   Problem: bywaf.plugin.toml must include a non-empty version string in the [plugin] table.",
                    '   Fix: add a line such as version = "0.1.0" under [plugin], or preserve this field when copying a skeleton manifest.',
                ]
            )
            item_number += 1
            continue
        lines.extend(
            [
                f"{item_number}. Checker error",
                f"   Problem: {error}",
                "   Fix: correct the plugin so scripts/plugin_check.py can import and validate it.",
            ]
        )
        item_number += 1
    return "\n".join(lines)


def format_capability_codes(capability_codes: dict[str, Any]) -> str:
    """Return compact capability-to-code display text."""
    return ", ".join(f"{capability}={code}" for capability, code in sorted(capability_codes.items()))
