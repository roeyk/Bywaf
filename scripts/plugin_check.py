#!/usr/bin/env python3
"""Developer tool for validating plugin manifests and metadata.

Provides checks for plugin TOML manifests, command specs, signature policy, and
catalog compatibility outside the Bywaf interpreter.

Used by:
- plugin authors and maintainers: catch metadata issues before release.
- tests: verify plugin validation behavior."""


from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bywaf.event_schemas import event_schema  # noqa: E402
from bywaf.plugin.capabilities import capability_declared  # noqa: E402
from bywaf.registry import PluginManifestTrust, verify_plugin_manifest_signature_data, load_filesystem_plugin_package  # noqa: E402
from bywaf.toml_support import load_data_file  # noqa: E402
from bywaf.tools.plugin_check import analyze_plugin_source  # noqa: E402


def check_plugin(
    plugin_dir: Path,
    *,
    manifest_key: Path | None = None,
    verify_manifest: bool = False,
    strict_inference: bool = False,
) -> dict[str, Any]:
    """Return a validation report for one filesystem plugin directory."""
    report: dict[str, Any] = {
        "ok": False,
        "plugin": str(plugin_dir),
        "commandlets": [],
        "triggers": [],
        "declared_capabilities": [],
        "declared_emits": [],
        "inferred_capabilities": [],
        "inferred_emits": [],
        "missing_capabilities": [],
        "missing_shared_emits": [],
        "unused_capabilities": [],
        "evidence": [],
        "warnings": [],
        "diagnostics": [],
        "manifest_signature": "unchecked",
        "errors": [],
    }
    if not plugin_dir.exists():
        report["errors"].append(f"{plugin_dir} not found")
        return report
    if not plugin_dir.is_dir():
        report["errors"].append(f"{plugin_dir} is not a directory")
        return report
    missing = [str(path) for path in (plugin_dir / "plugin.py", plugin_dir / "bywaf.plugin.toml") if not path.exists()]
    if missing:
        report["errors"].extend(f"{path} not found" for path in missing)
        return report
    try:
        source_analysis = analyze_plugin_source(plugin_dir)
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(f"source analysis failed: {exc}")
        return report
    report.update(source_analysis.to_dict())
    source_errors = [item for item in report["diagnostics"] if item.get("severity") == "error"]
    report["errors"].extend(f"{item['code']}: {item['message']}" for item in source_errors)
    if verify_manifest and manifest_key is None:
        report["errors"].append("--verify requires --manifest-key")
        return report
    if manifest_key is not None:
        try:
            verify_plugin_manifest_signature_data(load_data_file(plugin_dir / "bywaf.plugin.toml"), manifest_key, plugin_dir / "bywaf.plugin.toml")
        except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
            report["manifest_signature"] = "failed"
            report["errors"].append(str(exc))
            return report
        report["manifest_signature"] = "verified"
    try:
        plugins, triggers, manifest = load_filesystem_plugin_package(
            plugin_dir,
            manifest_trust=PluginManifestTrust(public_key_path=manifest_key, catalog_verified=manifest_key is None),
        )
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(str(exc))
        return report
    report["commandlets"] = [plugin.spec.name for plugin in plugins]
    report["triggers"] = [trigger.name for trigger in triggers]
    declared_capabilities = sorted({capability for plugin in plugins for capability in plugin.spec.capabilities})
    report["declared_capabilities"] = declared_capabilities
    declared_emits = sorted({topic for topics in manifest.commandlet_emits.values() for topic in topics})
    report["declared_emits"] = declared_emits
    inferred_capabilities = tuple(str(item) for item in report["inferred_capabilities"])
    inferred_emits = tuple(str(item) for item in report["inferred_emits"])
    missing_capabilities = sorted(
        capability
        for capability in inferred_capabilities
        if not capability_declared(capability, declared_capabilities)
    )
    observed_capabilities = tuple(
        sorted(
            {
                *inferred_capabilities,
                *(str(item.get("capability")) for item in report.get("warnings", ())),
            }
        )
    )
    unused_capabilities = sorted(
        capability
        for capability in declared_capabilities
        if not capability_declared(capability, observed_capabilities)
    )
    report["missing_capabilities"] = missing_capabilities
    report["unused_capabilities"] = unused_capabilities
    missing_shared_emits = sorted(
        topic
        for topic in inferred_emits
        if event_schema(topic) is not None and topic not in declared_emits
    )
    report["missing_shared_emits"] = missing_shared_emits
    if strict_inference and missing_capabilities:
        report["errors"].append("missing inferred capabilities: " + ", ".join(missing_capabilities))
    if missing_shared_emits:
        report["errors"].append("missing shared event emits declarations: " + ", ".join(missing_shared_emits))
    report["ok"] = not report["errors"]
    return report


def render_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output."""
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']}"]
    commandlets = report.get("commandlets") or []
    triggers = report.get("triggers") or []
    errors = report.get("errors") or []
    missing_capabilities = report.get("missing_capabilities") or []
    missing_shared_emits = report.get("missing_shared_emits") or []
    unused_capabilities = report.get("unused_capabilities") or []
    inferred_capabilities = report.get("inferred_capabilities") or []
    inferred_emits = report.get("inferred_emits") or []
    warnings = report.get("warnings") or []
    diagnostics = report.get("diagnostics") or []
    if commandlets:
        lines.append("commandlets: " + ", ".join(str(item) for item in commandlets))
    if triggers:
        lines.append("triggers: " + ", ".join(str(item) for item in triggers))
    if inferred_capabilities:
        lines.append("inferred capabilities: " + ", ".join(str(item) for item in inferred_capabilities))
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
    lines = [f"{'PASSED' if report['ok'] else 'FAILED'}: Bywaf plugin check", f"Plugin: {report['plugin']}"]
    diagnostics = report.get("diagnostics") or []
    errors = report.get("errors") or []
    warnings = report.get("warnings") or []
    missing_capabilities = report.get("missing_capabilities") or []
    missing_shared_emits = report.get("missing_shared_emits") or []
    unused_capabilities = report.get("unused_capabilities") or []
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
        lines.extend(
            [
                f"{item_number}. Missing capability declaration: {capability}",
                "   Problem: source analysis inferred this capability but it is not declared.",
                "   Fix: add the capability to the @commandlet(..., capabilities=(...)) tuple and the matching "
                "bywaf.plugin.toml [[commandlets]] capabilities list.",
            ]
        )
        item_number += 1
    for warning in warnings:
        lines.extend(
            [
                f"{item_number}. {warning['path']}:{warning['line']} [{warning['kind']}]",
                f"   Problem: direct {warning['capability']} use detected: {warning['detail']}",
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
        lines.extend(
            [
                f"{item_number}. Possibly unused declared capability: {capability}",
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
        lines.extend(
            [
                f"{item_number}. Checker error",
                f"   Problem: {error}",
                "   Fix: correct the plugin so scripts/plugin_check.py can import and validate it.",
            ]
        )
        item_number += 1
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Build the plugin-check CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_check.py")
    parser.add_argument("plugin", type=Path, help="filesystem plugin directory containing plugin.py and bywaf.plugin.toml")
    parser.add_argument("--manifest-key", type=Path, help="trusted public key for verifying bywaf.plugin.toml")
    parser.add_argument("--verify", action="store_true", help="require a verified manifest signature")
    parser.add_argument(
        "--strict-inference",
        action="store_true",
        help="fail when AST-inferred capabilities are missing from CommandSpec declarations",
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable validation report")
    parser.add_argument("--llm-feedback", action="store_true", help="emit concise feedback suitable for pasting into an LLM chat")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run plugin package validation."""
    args = build_parser().parse_args(argv)
    report = check_plugin(
        args.plugin,
        manifest_key=args.manifest_key,
        verify_manifest=args.verify,
        strict_inference=args.strict_inference,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.llm_feedback:
        print(render_llm_feedback(report))
    else:
        print(render_text(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
