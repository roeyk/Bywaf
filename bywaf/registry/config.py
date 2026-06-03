"""Plugin config and defaults loading helpers.

Provides parsing for plugin config files, package config resources, provider-name
derivation, and module/filesystem default-variable loading.

Used by:
- registry.core: reads provider lists and loads provider defaults.
- packaging smoke tests: verify bundled plugin config resources."""

from __future__ import annotations

import json
import tomllib
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

from ..plugin import Commandlet
from ..toml_support import load_data_file
from ..varstore import VarStore


def load_module_defaults(module: ModuleType, plugin: Commandlet, varstore: VarStore, *, scope: str | None = None) -> None:
    """Import module-level DEFAULTS into the shared VarStore."""
    defaults = getattr(module, "DEFAULTS", None)
    if isinstance(defaults, dict):
        # Module DEFAULTS are convenience defaults, not authoritative manifest
        # metadata. They initialize unset commandlet variables for operators.
        varstore.update_prefixed(scope or plugin.spec.name, defaults)
    load_spec_defaults(plugin, varstore, scope=scope)


def load_defaults_file(plugin_dir: Path, plugin: Commandlet, varstore: VarStore, *, scope: str | None = None) -> None:
    """Load filesystem plugin defaults from TOML, with JSON compatibility."""
    path = first_existing(plugin_dir / "defaults.toml", plugin_dir / "defaults.json")
    if path is not None:
        values = load_data_file(path)
        varstore.update_prefixed(scope or plugin.spec.name, values.get("defaults", values))
    load_spec_defaults(plugin, varstore, scope=scope)


def load_spec_defaults(plugin: Commandlet, varstore: VarStore, *, scope: str | None = None) -> None:
    """Load declared option defaults from CommandSpec metadata."""
    defaults = {
        option.name: option.default
        for option in plugin.spec.options
        if option.default is not None
    }
    if defaults:
        varstore.update_prefixed(scope or plugin.spec.name, defaults)


def parse_plugin_config(path: Path) -> list[str]:
    """Parse TOML, JSON, or minimal YAML-style plugin config files."""
    text = path.read_text()
    if path.suffix in {".json", ".toml"}:
        data: Any = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
        return list(data.get("default_plugins", []))
    entries: list[str] = []
    in_default_plugins = False
    for raw_line in text.splitlines():
        # YAML support is intentionally tiny: only default_plugins: followed by
        # list items. Full YAML would add a dependency for little benefit here.
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "default_plugins:":
            in_default_plugins = True
            continue
        if in_default_plugins and line.startswith("- "):
            entries.append(line[2:].strip())
        elif not raw_line.startswith((" ", "\t")):
            in_default_plugins = False
    return entries


def parse_package_plugin_config(package_name: str, config_name: str) -> list[str]:
    """Read the bundled plugin config from package resources."""
    data = load_package_plugin_config(package_name, config_name)
    return list(data.get("default_plugins", []))


def parse_package_plugin_aliases(package_name: str, config_name: str) -> dict[str, str]:
    """Read bundled commandlet aliases from package resources."""
    aliases = load_package_plugin_config(package_name, config_name).get("commandlet_aliases", {})
    if not isinstance(aliases, dict):
        raise ValueError("commandlet_aliases must be a table")
    return {str(alias): str(commandlet) for alias, commandlet in aliases.items()}


def load_package_plugin_config(package_name: str, config_name: str) -> dict[str, Any]:
    """Return bundled plugin config data from package resources."""
    config = resources.files(package_name).joinpath(config_name)
    text = config.read_text(encoding="utf-8")
    data: Any = tomllib.loads(text) if config_name.endswith(".toml") else json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{config_name} must contain a table/object")
    return data


def provider_name(entry: str) -> str:
    """Derive top-level provider name from a dotted or slash catalog entry."""
    normalized = normalize_catalog_path(entry)
    return normalized.split("/", 1)[0]


def normalize_catalog_path(path: str) -> str:
    """Return a slash-delimited catalog path from dotted package or slash input."""
    normalized = path.replace(".", "/")
    parts = normalized.split("/")
    # Catalog paths are user-facing provider addresses. Reject traversal-like or
    # empty segments before they can become variable scopes.
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"invalid catalog path: {path}")
    return normalized


def first_existing(*paths: Path) -> Path | None:
    """Return the first existing path in priority order."""
    return next((path for path in paths if path.exists()), None)
