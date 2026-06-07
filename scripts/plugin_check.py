#!/usr/bin/env python3
"""Developer tool for validating plugin manifests and metadata.

Provides checks for plugin TOML manifests, command specs, signature policy, and
catalog compatibility outside the Bywaf interpreter.

Used by:
- plugin authors and maintainers: catch metadata issues before release.
- tests: verify plugin validation behavior."""


from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bywaf import __version__ as BYWAF_VERSION  # noqa: E402
from bywaf.event.schemas import event_schema, register_event_schemas  # noqa: E402
from bywaf.plugin.capabilities import capability_code_label, capability_declared  # noqa: E402
from bywaf.registry.config import parse_package_plugin_config  # noqa: E402
from bywaf.registry.loading import load_plugins, load_trigger_specs  # noqa: E402
from bywaf.registry.compat import satisfies_bywaf_requirement  # noqa: E402
from bywaf.registry import (  # noqa: E402
    PluginManifest,
    PluginManifestTrust,
    build_manifest_graph,
    build_package_manifest_graph,
    bundled_manifest_map,
    dependency_errors,
    enforce_plugin_manifest,
    enforce_trigger_manifest,
    load_filesystem_plugin_package,
    load_package_manifest,
    parse_plugin_manifest_data,
    registered_topics_for_graph,
    relationship_report_for_provider,
    verify_plugin_manifest_signature_data,
)
from bywaf.toml_support import load_data_file  # noqa: E402
from bywaf.tools.plugin_check import analyze_plugin_source  # noqa: E402
from bywaf.tools.plugin_parser_contract import parser_contract_diagnostics  # noqa: E402
from bywaf.tools.plugin_check_render import render_llm_feedback, render_text  # noqa: E402
from bywaf.tools.plugin_submission import check_plugin_in_temp_checkout, materialized_plugin_submission  # noqa: E402


def check_plugin(
    plugin_dir: Path,
    *,
    manifest_key: Path | None = None,
    verify_manifest: bool = False,
    strict_inference: bool = False,
    include_graph: bool = False,
) -> dict[str, Any]:
    """Return a validation report for one filesystem plugin directory."""
    original_plugin = plugin_dir
    report: dict[str, Any] = {
        "ok": False,
        "plugin": str(plugin_dir),
        "plugin_version": "",
        "requires_bywaf": None,
        "commandlets": [],
        "triggers": [],
        "declared_capabilities": [],
        "capability_codes": {},
        "declared_emits": [],
        "inferred_capabilities": [],
        "inferred_emits": [],
        "missing_capabilities": [],
        "missing_shared_emits": [],
        "unregistered_declared_emits": [],
        "unused_capabilities": [],
        "evidence": [],
        "warnings": [],
        "diagnostics": [],
        "manifest_signature": "unchecked",
        "errors": [],
    }
    try:
        with materialized_plugin_submission(plugin_dir) as materialized:
            materialized_report = check_materialized_plugin(
                materialized,
                manifest_key=manifest_key,
                verify_manifest=verify_manifest,
                strict_inference=strict_inference,
                include_graph=include_graph,
                report=report,
            )
            materialized_report["plugin"] = str(original_plugin)
            if original_plugin.is_dir() and materialized.resolve() != original_plugin.resolve():
                materialized_report["materialized_plugin"] = str(materialized)
            return materialized_report
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(str(exc))
        return report


def check_bundled_plugins(*, strict_inference: bool = False, include_graph: bool = False) -> dict[str, Any]:
    """Return validation results for every bundled plugin config entry."""
    reports = [
        check_bundled_plugin(entry, strict_inference=strict_inference)
        for entry in parse_package_plugin_config("bywaf.plugins", "plugins.toml")
    ]
    report: dict[str, Any] = {
        "ok": all(report["ok"] for report in reports),
        "plugin": "bywaf.plugins",
        "checked": len(reports),
        "plugins": reports,
        "errors": [f"{report['entry']}: {error}" for report in reports for error in report.get("errors", [])],
    }
    if include_graph:
        report["relationship_graph"] = build_package_manifest_graph("bywaf.plugins", "plugins.toml").to_dict()
    return report


def check_bundled_plugin(entry: str, *, strict_inference: bool = False) -> dict[str, Any]:
    """Return a validation report for one bundled plugin config entry."""
    report = {
        "ok": False,
        "plugin": f"bywaf.plugins.{entry}",
        "entry": entry,
        "plugin_version": "",
        "requires_bywaf": None,
        "commandlets": [],
        "triggers": [],
        "declared_capabilities": [],
        "capability_codes": {},
        "declared_emits": [],
        "inferred_capabilities": [],
        "inferred_emits": [],
        "missing_capabilities": [],
        "missing_shared_emits": [],
        "unregistered_declared_emits": [],
        "unused_capabilities": [],
        "evidence": [],
        "warnings": [],
        "diagnostics": [],
        "manifest_signature": "bundled",
        "errors": [],
    }
    try:
        manifest = load_package_manifest("bywaf.plugins", entry)
        if manifest is None:
            report["errors"].append("bundled plugin manifest is required")
            return report
        register_event_schemas(manifest.event_schemas)
        report["plugin_version"] = manifest.version
        report["requires_bywaf"] = manifest.requires_bywaf
        report["errors"].extend(dependency_errors(entry, manifest, bundled_graph()))
        module = importlib.import_module(f"bywaf.plugins.{entry}")
        plugins = enforce_plugin_manifest(
            manifest,
            load_plugins(module),
            Path(f"bywaf.plugins.{entry}.plugin.toml"),
            hydrate_specs=True,
        )
        triggers = enforce_trigger_manifest(manifest, load_trigger_specs(module), Path(f"bywaf.plugins.{entry}.plugin.toml"))
        source_path = bundled_source_path(module)
        source_analysis = analyze_plugin_source(source_path)
        report.update(source_analysis.to_dict())
        report["commandlets"] = [plugin.spec.name for plugin in plugins]
        report["triggers"] = [trigger.name for trigger in triggers]
        parser_diagnostics = parser_contract_diagnostics(plugins, source_path)
        report["diagnostics"].extend(parser_diagnostics)
        report["errors"].extend(f"{item['code']}: {item['message']}" for item in parser_diagnostics if item["severity"] == "error")
        declared_capabilities = sorted({capability for plugin in plugins for capability in plugin.spec.capabilities})
        report["declared_capabilities"] = declared_capabilities
        declared_emits = sorted({topic for topics in manifest.commandlet_emits.values() for topic in topics})
        report["declared_emits"] = declared_emits
        finalize_inference_report(report, declared_capabilities, declared_emits, strict_inference=strict_inference)
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(str(exc))
    report["ok"] = not report["errors"]
    return report


def bundled_source_path(module: Any) -> Path:
    """Return the source file or package directory for a bundled plugin module."""
    module_file = Path(str(module.__file__))
    return module_file.parent if module_file.name == "__init__.py" else module_file


def check_materialized_plugin(
    plugin_dir: Path,
    *,
    manifest_key: Path | None,
    verify_manifest: bool,
    strict_inference: bool,
    include_graph: bool,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Validate an already-unpacked filesystem plugin directory."""
    missing = [str(path) for path in (plugin_dir / "plugin.py", plugin_dir / "bywaf.plugin.toml") if not path.exists()]
    if missing:
        report["errors"].extend(f"{path} not found" for path in missing)
        return report
    try:
        manifest_data = load_data_file(plugin_dir / "bywaf.plugin.toml")
        plugin_data = manifest_data.get("plugin", {})
        if not isinstance(plugin_data, dict) or not isinstance(plugin_data.get("version"), str) or not plugin_data.get("version"):
            report["errors"].append("manifest [plugin].version is required")
            return report
        pre_import_manifest = parse_plugin_manifest_data(manifest_data, str(plugin_dir / "bywaf.plugin.toml"))
        register_event_schemas(pre_import_manifest.event_schemas)
        report["plugin_version"] = pre_import_manifest.version
        report["requires_bywaf"] = pre_import_manifest.requires_bywaf
        if include_graph:
            report["relationship_graph"] = filesystem_plugin_relationship_report(
                plugin_dir.name,
                pre_import_manifest,
            )
        report["errors"].extend(filesystem_dependency_errors(plugin_dir.name, pre_import_manifest))
        if not satisfies_bywaf_requirement(BYWAF_VERSION, pre_import_manifest.requires_bywaf):
            report["errors"].append(
                f"requires Bywaf {pre_import_manifest.requires_bywaf}, current Bywaf is {BYWAF_VERSION}"
            )
            return report
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(f"manifest parse failed: {exc}")
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
    parser_diagnostics = parser_contract_diagnostics(plugins, plugin_dir / "plugin.py")
    report["diagnostics"].extend(parser_diagnostics)
    report["errors"].extend(f"{item['code']}: {item['message']}" for item in parser_diagnostics if item["severity"] == "error")
    declared_capabilities = sorted({capability for plugin in plugins for capability in plugin.spec.capabilities})
    report["declared_capabilities"] = declared_capabilities
    declared_emits = sorted({topic for topics in manifest.commandlet_emits.values() for topic in topics})
    report["declared_emits"] = declared_emits
    finalize_inference_report(report, declared_capabilities, declared_emits, strict_inference=strict_inference)
    report["ok"] = not report["errors"]
    return report


def filesystem_plugin_relationship_report(provider: str, manifest: PluginManifest) -> dict[str, object]:
    """Return relationship context for one filesystem plugin plus bundled manifests."""
    graph = build_manifest_graph({**bundled_manifest_map(), f"filesystem:{provider}": manifest})
    return relationship_report_for_provider(
        graph,
        f"filesystem:{provider}",
        registered_schemas=registered_topics_for_graph(graph),
    )


def filesystem_dependency_errors(provider: str, manifest: PluginManifest) -> list[str]:
    """Return dependency diagnostics for one filesystem plugin."""
    graph = build_manifest_graph({**bundled_manifest_map(), f"filesystem:{provider}": manifest})
    return dependency_errors(f"filesystem:{provider}", manifest, graph)


def bundled_graph() -> Any:
    """Return the current bundled manifest graph."""
    return build_package_manifest_graph("bywaf.plugins", "plugins.toml")


def finalize_inference_report(
    report: dict[str, Any],
    declared_capabilities: list[str],
    declared_emits: list[str],
    *,
    strict_inference: bool,
) -> None:
    """Populate capability and emits drift fields on a checker report."""
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
    report["capability_codes"] = capability_code_map(
        (
            *declared_capabilities,
            *inferred_capabilities,
            *missing_capabilities,
            *unused_capabilities,
            *(str(item.get("capability")) for item in report.get("warnings", ())),
        )
    )
    missing_shared_emits = sorted(
        topic
        for topic in inferred_emits
        if event_schema(topic) is not None and topic not in declared_emits
    )
    report["missing_shared_emits"] = missing_shared_emits
    report["unregistered_declared_emits"] = sorted(
        topic for topic in declared_emits if event_schema(topic) is None
    )
    if strict_inference and missing_capabilities:
        report["errors"].append("missing inferred capabilities: " + ", ".join(missing_capabilities))
    if missing_shared_emits:
        report["errors"].append("missing shared event emits declarations: " + ", ".join(missing_shared_emits))


def capability_code_map(capabilities: Iterable[str]) -> dict[str, str]:
    """Return stable display labels for capability names."""
    return {capability: capability_code_label(capability) for capability in sorted(set(capabilities))}


def build_parser() -> argparse.ArgumentParser:
    """Build the plugin-check CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_check.py")
    parser.add_argument("plugin", nargs="?", type=Path, help="filesystem plugin directory or .zip containing plugin.py and bywaf.plugin.toml")
    parser.add_argument("--all", action="store_true", help="validate every bundled plugin listed in bywaf.plugins/plugins.toml")
    parser.add_argument("--manifest-key", type=Path, help="trusted public key for verifying bywaf.plugin.toml")
    parser.add_argument("--verify", action="store_true", help="require a verified manifest signature")
    parser.add_argument(
        "--temp-checkout",
        action="store_true",
        help="copy this Bywaf tree to a temp checkout, apply the plugin submission, and validate from there",
    )
    parser.add_argument("--no-temp-checkout", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--strict-inference",
        action="store_true",
        help="fail when AST-inferred capabilities are missing from CommandSpec declarations",
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable validation report")
    parser.add_argument("--llm-feedback", action="store_true", help="emit concise feedback suitable for pasting into an LLM chat")
    parser.add_argument("--graph", action="store_true", help="include manifest relationship graph context")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run plugin package validation."""
    args = build_parser().parse_args(argv)
    if args.all:
        report = check_bundled_plugins(strict_inference=args.strict_inference, include_graph=args.graph)
    elif args.plugin is None:
        raise SystemExit("plugin path is required unless --all is used")
    elif args.temp_checkout and not args.no_temp_checkout:
        report = check_plugin_in_temp_checkout(
            args.plugin,
            checkout_source=ROOT,
            manifest_key=args.manifest_key,
            verify_manifest=args.verify,
            strict_inference=args.strict_inference,
            include_graph=args.graph,
        )
    else:
        report = check_plugin(
            args.plugin,
            manifest_key=args.manifest_key,
            verify_manifest=args.verify,
            strict_inference=args.strict_inference,
            include_graph=args.graph,
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
