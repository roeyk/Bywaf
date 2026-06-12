"""Bundled plugin manual drift checks.

Verifies that the operator-facing bundled plugin manual still matches bundled
plugin manifests for plugin names, family counts, commandlet counts, and
commandlet headings.

Used by:
- maintainer tools, documentation/report generation, and validation scripts.
- tests and release checks that exercise developer-facing tooling.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PLUGIN_HEADING_RE = re.compile(r"^### `([^`]+)`$")
COMMANDLET_HEADING_RE = re.compile(r"^#### Commandlets?: (.+)$")
FAMILY_HEADING_RE = re.compile(r"^## ([A-Za-z]+)$")

# These patterns parse generated HTML fragments embedded in
# BUNDLED_PLUGIN_MANUAL.md. `parse_manual()` uses them as a small state machine
# for the collapsible top-level plugin table of contents.
TOC_SUMMARY_RE = re.compile(
    r'<summary id="toc-([^"]+)"><span class="toc-count">(\d+)</span>.*?'
    r'<span class="toc-name">([^<]+)</span></summary>'
)
TOC_ENTRY_RE = re.compile(
    r'<div class="toc-entry"><span class="toc-count toc-child-count">(\d+)</span>'
    r'<span class="toc-name"><a href="#([^"]+)">([^<]+)</a></span></div>'
)
BACKTICK_NAME_RE = re.compile(r"`([^`]+)`")

# The checker treats this exact header as part of the generated-manual
# contract. If it disappears, the manual still has sections but loses the
# operator-friendly count legend.
TOC_HEADER = (
    '<div class="toc-header"><span class="toc-count">Plugins (Commandlets)</span>'
    '<span class="toc-name">Name</span></div>'
)

# These are manual section headings, not package namespaces. display_family()
# maps a manifest's top-level package to one of these display families.
FAMILY_NAMES = {
    "Analysis",
    "Discovery",
    "HTTP",
    "Identity",
    "Network",
    "OS",
    "Recon",
    "Runtime",
    "Storage",
    "Wireless",
}


@dataclass(frozen=True, slots=True)
class PluginManualEntry:
    """Manifest-derived bundled plugin shape.

    Constructed by: `entry_from_manifest()`.
    Consumed by: `check_manual()` when comparing generated documentation with
    bundled plugin sidecars.
    """

    family: str
    plugin: str
    commandlets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ManualShape:
    """Manual-derived bundled plugin shape.

    Constructed by: `parse_manual()`.
    Consumed by: `check_manual()` to compare top TOC counts, plugin sections,
    and commandlet headings against manifest-derived expectations.
    """

    toc_counts: dict[str, int]
    toc_plugins: dict[str, dict[str, int]]
    sections: dict[str, str]
    commandlets: dict[str, tuple[str, ...]]
    has_toc_header: bool


def collect_bundled_plugins(plugin_root: Path) -> tuple[PluginManualEntry, ...]:
    """Return bundled plugin metadata from manifests under `plugin_root`."""
    entries: list[PluginManualEntry] = []
    for manifest_path in sorted(plugin_root.rglob("*.plugin.toml")):
        # The checker scans manifests only; importing plugin modules would make
        # documentation drift checks slower and sensitive to optional tools.
        plugin = plugin_name_for_manifest(plugin_root, manifest_path)
        entries.append(entry_from_manifest(manifest_path, plugin))
    return tuple(sorted(entries, key=lambda entry: entry.plugin))


def plugin_name_for_manifest(plugin_root: Path, manifest_path: Path) -> str:
    """Return dotted plugin name for a bundled manifest path."""
    relative = manifest_path.relative_to(plugin_root)
    # Package-local manifests are named bywaf.plugin.toml and use their parent
    # package path as the plugin id; legacy flat manifests use their stem.
    if relative.name == "bywaf.plugin.toml":
        parts = relative.parent.parts
    else:
        parts = (*relative.parent.parts, relative.stem.removesuffix(".plugin"))
    return ".".join(parts)


def entry_from_manifest(manifest_path: Path, plugin: str) -> PluginManualEntry:
    """Build one plugin manual entry from a manifest file."""
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    rows = data.get("commandlets")
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{manifest_path} must declare at least one [[commandlets]] entry")
    commandlets: list[str] = []
    for index, row in enumerate(rows, start=1):
        # Keep validation strict here because a malformed commandlet row would
        # make the generated manual ambiguous.
        if not isinstance(row, dict):
            raise ValueError(f"{manifest_path} commandlets entry {index} must be a table")
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{manifest_path} commandlets entry {index} requires name")
        commandlets.append(name)
    return PluginManualEntry(
        family=display_family(plugin.split(".", maxsplit=1)[0]),
        plugin=plugin,
        commandlets=tuple(sorted(commandlets)),
    )


def display_family(name: str) -> str:
    """Return manual display family for a plugin namespace."""
    if name in {"http", "os"}:
        return name.upper()
    return name.replace("_", " ").title().replace(" ", "")


def parse_manual(path: Path) -> ManualShape:
    """Parse the manual's plugin TOC and plugin sections."""
    lines = path.read_text(encoding="utf-8").splitlines()
    toc_counts: dict[str, int] = {}
    toc_plugins: dict[str, dict[str, int]] = {}
    sections: dict[str, str] = {}
    commandlets: dict[str, list[str]] = {}
    current_toc_family: str | None = None
    current_section_family: str | None = None
    current_plugin: str | None = None
    has_toc_header = TOC_HEADER in lines

    for line in lines:
        # First parse the generated top TOC. current_toc_family tracks the
        # enclosing <details> section until its closing tag is seen.
        summary_match = TOC_SUMMARY_RE.match(line)
        if summary_match:
            _anchor, count, family = summary_match.groups()
            current_toc_family = family
            toc_counts[family] = int(count)
            toc_plugins.setdefault(family, {})
            continue
        if line == "</details>":
            current_toc_family = None
            continue
        entry_match = TOC_ENTRY_RE.match(line)
        if entry_match and current_toc_family is not None:
            count, _anchor, plugin = entry_match.groups()
            toc_plugins.setdefault(current_toc_family, {})[plugin] = int(count)
            continue

        # Then parse the Markdown body. current_section_family and
        # current_plugin identify which heading owns the next commandlet row.
        family_match = FAMILY_HEADING_RE.match(line)
        if family_match and family_match.group(1) in FAMILY_NAMES:
            current_section_family = family_match.group(1)
            current_plugin = None
            continue
        plugin_match = PLUGIN_HEADING_RE.match(line)
        if plugin_match and current_section_family is not None:
            plugin = plugin_match.group(1)
            current_plugin = plugin
            sections[plugin] = current_section_family
            commandlets.setdefault(plugin, [])
            continue
        commandlet_match = COMMANDLET_HEADING_RE.match(line)
        if commandlet_match and current_plugin is not None:
            commandlets[current_plugin].extend(BACKTICK_NAME_RE.findall(commandlet_match.group(1)))

    return ManualShape(
        toc_counts=toc_counts,
        toc_plugins=toc_plugins,
        sections=sections,
        commandlets={name: tuple(sorted(values)) for name, values in commandlets.items()},
        has_toc_header=has_toc_header,
    )


def check_manual(
    manual_path: Path,
    plugin_root: Path,
) -> list[str]:
    """Return drift errors between the manual and bundled plugin manifests."""
    expected = collect_bundled_plugins(plugin_root)
    manual = parse_manual(manual_path)
    errors: list[str] = []
    if not manual.has_toc_header:
        errors.append("top TOC header row is missing")

    expected_by_plugin = {entry.plugin: entry for entry in expected}
    section_plugins = set(manual.sections)
    toc_plugins = {plugin for plugins in manual.toc_plugins.values() for plugin in plugins}
    expected_plugins = set(expected_by_plugin)

    # Presence checks catch missing or stale plugin sections before comparing
    # per-plugin details.
    errors.extend(compare_sets("manual plugin sections", expected_plugins, section_plugins))
    errors.extend(compare_sets("top TOC plugins", expected_plugins, toc_plugins))

    expected_family_counts = count_by_family(expected)
    if manual.toc_counts != expected_family_counts:
        errors.append(
            "top TOC family counts differ: "
            f"expected {format_mapping(expected_family_counts)}, "
            f"found {format_mapping(manual.toc_counts)}"
        )

    for plugin, entry in expected_by_plugin.items():
        # Family placement, TOC counts, and commandlet headings are compared
        # independently so the report points at the exact drift.
        section_family = manual.sections.get(plugin)
        if section_family is not None and section_family != entry.family:
            errors.append(f"{plugin} section is under {section_family}, expected {entry.family}")
        toc_family = family_for_toc_plugin(manual.toc_plugins, plugin)
        if toc_family is not None and toc_family != entry.family:
            errors.append(f"{plugin} top TOC entry is under {toc_family}, expected {entry.family}")
        toc_count = manual.toc_plugins.get(entry.family, {}).get(plugin)
        if toc_count is not None and toc_count != len(entry.commandlets):
            errors.append(
                f"{plugin} top TOC commandlet count is {toc_count}, "
                f"expected {len(entry.commandlets)}"
            )
        manual_commandlets = manual.commandlets.get(plugin)
        if manual_commandlets is not None and manual_commandlets != entry.commandlets:
            errors.append(
                f"{plugin} commandlets differ: expected {', '.join(entry.commandlets)}, "
                f"found {', '.join(manual_commandlets)}"
            )
    return errors


def count_by_family(entries: tuple[PluginManualEntry, ...]) -> dict[str, int]:
    """Return sorted plugin counts by family."""
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.family] = counts.get(entry.family, 0) + 1
    return dict(sorted(counts.items()))


def family_for_toc_plugin(toc_plugins: dict[str, dict[str, int]], plugin: str) -> str | None:
    """Return the manual TOC family containing `plugin`."""
    for family, plugins in toc_plugins.items():
        if plugin in plugins:
            return family
    return None


def compare_sets(label: str, expected: set[str], found: set[str]) -> list[str]:
    """Return missing/extra item errors."""
    errors: list[str] = []
    missing = sorted(expected.difference(found))
    extra = sorted(found.difference(expected))
    if missing:
        errors.append(f"{label} missing: {', '.join(missing)}")
    if extra:
        errors.append(f"{label} extra: {', '.join(extra)}")
    return errors


def format_mapping(values: dict[str, int]) -> str:
    """Return deterministic mapping text for diagnostics."""
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items()))


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(prog="bundled_plugin_manual_check")
    parser.add_argument("--manual", default="docs/BUNDLED_PLUGIN_MANUAL.md")
    parser.add_argument("--plugins", default="bywaf/plugins")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    args = build_parser().parse_args(argv)
    manual_path = Path(args.manual)
    plugin_root = Path(args.plugins)
    errors = check_manual(manual_path, plugin_root)
    if args.json:
        import json

        report: dict[str, Any] = {"ok": not errors, "errors": errors}
        print(json.dumps(report, indent=2, sort_keys=True))
    elif errors:
        print("bundled plugin manual drift found:")
        for error in errors:
            print(f"- {error}")
    else:
        print("ok bundled_plugin_manual plugins match manifests")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
