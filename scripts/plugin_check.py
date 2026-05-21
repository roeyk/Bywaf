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

from bywaf.registry import PluginManifestTrust, verify_plugin_manifest_signature_data, load_filesystem_plugin_package  # noqa: E402
from bywaf.toml_support import load_data_file  # noqa: E402


def check_plugin(
    plugin_dir: Path,
    *,
    manifest_key: Path | None = None,
    verify_manifest: bool = False,
) -> dict[str, Any]:
    """Return a validation report for one filesystem plugin directory."""
    report: dict[str, Any] = {
        "ok": False,
        "plugin": str(plugin_dir),
        "commandlets": [],
        "triggers": [],
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
        plugins, triggers = load_filesystem_plugin_package(
            plugin_dir,
            manifest_trust=PluginManifestTrust(public_key_path=manifest_key, catalog_verified=manifest_key is None),
        )
    except Exception as exc:  # noqa: BLE001 - this is a CLI validation report.
        report["errors"].append(str(exc))
        return report
    report["ok"] = True
    report["commandlets"] = [plugin.spec.name for plugin in plugins]
    report["triggers"] = [trigger.name for trigger in triggers]
    return report


def render_text(report: dict[str, Any]) -> str:
    """Return human-readable validation output."""
    lines = [f"{'ok' if report['ok'] else 'failed'} plugin={report['plugin']}"]
    commandlets = report.get("commandlets") or []
    triggers = report.get("triggers") or []
    errors = report.get("errors") or []
    if commandlets:
        lines.append("commandlets: " + ", ".join(str(item) for item in commandlets))
    if triggers:
        lines.append("triggers: " + ", ".join(str(item) for item in triggers))
    for error in errors:
        lines.append(f"error: {error}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Build the plugin-check CLI parser."""
    parser = argparse.ArgumentParser(prog="scripts/plugin_check.py")
    parser.add_argument("plugin", type=Path, help="filesystem plugin directory containing plugin.py and bywaf.plugin.toml")
    parser.add_argument("--manifest-key", type=Path, help="trusted public key for verifying bywaf.plugin.toml")
    parser.add_argument("--verify", action="store_true", help="require a verified manifest signature")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable validation report")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run plugin package validation."""
    args = build_parser().parse_args(argv)
    report = check_plugin(args.plugin, manifest_key=args.manifest_key, verify_manifest=args.verify)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
