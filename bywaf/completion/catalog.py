"""Catalog-backed completion helpers.

Provides local plugin catalog path and not-yet-loaded manifest variable
completion so operators can discover plugin settings before import.

Used by:
- completion.engine: exposes catalog paths and unloaded plugin variables.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..registry.config import normalize_catalog_path
from ..registry.manifest import parse_plugin_manifest
from ..toml_support import load_data_file

if TYPE_CHECKING:
    from ..registry import PluginRegistry


class CatalogCompletionMixin:
    """Completion helpers backed by local plugin catalog files."""

    registry: "PluginRegistry"

    def catalog_path_candidates(self, prefix: str) -> list[str]:
        """Complete known loaded provider and commandlet catalog paths."""
        paths = {*self.registry.provider_commandlets.keys(), *self.registry.commandlet_aliases()}
        return sorted(path for path in paths if path.startswith(prefix))

    def catalog_variable_names(self) -> list[str]:
        """Return variable names known from not-yet-loaded local plugin manifests/defaults."""
        plugin_root = Path(".bywaf/plugins")
        if not plugin_root.exists():
            return []
        names: set[str] = set()
        for manifest_path in plugin_root.rglob("bywaf.plugin.toml"):
            plugin_dir = manifest_path.parent
            try:
                provider_path = normalize_catalog_path(plugin_dir.relative_to(plugin_root).as_posix())
                manifest = parse_plugin_manifest(manifest_path)
            except (OSError, ValueError):
                continue
            default_names = filesystem_default_names(plugin_dir)
            for commandlet in manifest.commandlets:
                scope = f"{provider_path}/{commandlet}"
                for option in manifest.commandlet_options.get(commandlet, ()):
                    names.add(f"{scope}.{option.name}")
                for option in manifest.commandlet_secret_options.get(commandlet, ()):
                    names.add(f"{scope}.{option}")
                for option in manifest.commandlet_provider_variables.get(commandlet, ()):
                    names.add(f"{provider_path}.{option}")
                for option in manifest.commandlet_secret_vars.get(commandlet, ()):
                    names.add(f"{provider_path}.{option}")
                for name in default_names:
                    names.add(f"{scope}.{name}")
        return sorted(names)


def filesystem_default_names(plugin_dir: Path) -> set[str]:
    """Return default variable names from a local filesystem plugin package."""
    for filename in ("defaults.toml", "defaults.json"):
        path = plugin_dir / filename
        if not path.exists():
            continue
        try:
            data = load_data_file(path)
        except (OSError, ValueError):
            return set()
        values = data.get("defaults", data)
        if isinstance(values, dict):
            return {str(key) for key in values if isinstance(key, str)}
    return set()
