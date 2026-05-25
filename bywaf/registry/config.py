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
        varstore.update_prefixed(scope or plugin.spec.name, defaults)


def load_defaults_file(plugin_dir: Path, plugin: Commandlet, varstore: VarStore, *, scope: str | None = None) -> None:
    """Load filesystem plugin defaults from TOML, with JSON compatibility."""
    path = first_existing(plugin_dir / "defaults.toml", plugin_dir / "defaults.json")
    if path is None:
        return
    values = load_data_file(path)
    varstore.update_prefixed(scope or plugin.spec.name, values.get("defaults", values))


def parse_plugin_config(path: Path) -> list[str]:
    """Parse TOML, JSON, or minimal YAML-style plugin config files."""
    text = path.read_text()
    if path.suffix in {".json", ".toml"}:
        data: Any = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
        return list(data.get("default_plugins", []))
    entries: list[str] = []
    in_default_plugins = False
    for raw_line in text.splitlines():
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
    config = resources.files(package_name).joinpath(config_name)
    text = config.read_text(encoding="utf-8")
    data: Any = tomllib.loads(text) if config_name.endswith(".toml") else json.loads(text)
    return list(data.get("default_plugins", []))


def provider_name(entry: str) -> str:
    """Derive provider name from a dotted plugin config entry."""
    return entry.split(".", 1)[0] if "." in entry else entry


def first_existing(*paths: Path) -> Path | None:
    """Return the first existing path in priority order."""
    return next((path for path in paths if path.exists()), None)
