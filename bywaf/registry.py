"""Plugin discovery."""

from __future__ import annotations

import importlib
import importlib.util
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

from .plugin import Commandlet
from .varstore import VarStore


@dataclass(slots=True)
class PluginRegistry:
    """Loaded commandlets plus their provider grouping and shared variables."""

    plugins: dict[str, Commandlet]
    varstore: VarStore = field(default_factory=VarStore)
    providers: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def discover(
        cls,
        package_name: str = "bywaf.plugins",
        *,
        config_name: str = "plugins.json",
        varstore: VarStore | None = None,
    ) -> "PluginRegistry":
        """Load bundled plugins from a package-level config file."""
        entries = parse_package_plugin_config(package_name, config_name)
        store = varstore or VarStore()
        registry = cls({}, store)
        for entry in entries:
            registry.load_package_entry(package_name, entry)
        return registry

    @classmethod
    def from_config(
        cls,
        plugin_root: Path | str,
        config_file: Path | str,
        *,
        varstore: VarStore | None = None,
    ) -> "PluginRegistry":
        """Load plugins from an explicit filesystem config file."""
        registry = cls({}, varstore or VarStore())
        for entry in parse_plugin_config(Path(config_file)):
            registry.load_filesystem_entry(Path(plugin_root), entry)
        return registry

    def load_filesystem_entry(self, plugin_root: Path, entry: str) -> Commandlet:
        """Load `.plugin()` from `<plugin_root>/<entry>/plugin.py`."""
        plugin_dir = plugin_root / entry
        plugin = load_plugin_path(plugin_dir / "plugin.py")
        self.plugins[plugin.spec.name] = plugin
        self.providers.setdefault(provider_name(entry), []).append(plugin.spec.name)
        load_defaults_file(plugin_dir / "defaults.json", plugin, self.varstore)
        return plugin

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name."""
        module = importlib.import_module(f"{package_name}.{entry}")
        plugins = load_plugins(module)
        for plugin in plugins:
            self.plugins[plugin.spec.name] = plugin
            self.providers.setdefault(provider_name(entry), []).append(plugin.spec.name)
            load_module_defaults(module, plugin, self.varstore)
        return plugins[0]

    def get(self, name: str) -> Commandlet:
        """Return a commandlet by user-facing command name."""
        try:
            return self.plugins[name]
        except KeyError as exc:
            raise KeyError(f"unknown commandlet: {name}") from exc

    def names(self) -> list[str]:
        """Return commandlet names for command completion."""
        return sorted(self.plugins)

    def provider_names(self) -> list[str]:
        """Return provider names for the `plugins` command."""
        return sorted(self.providers)

    def grouped_names(self) -> dict[str, list[str]]:
        """Return commandlets grouped by provider for the `cmds` command."""
        return {provider: sorted(set(names)) for provider, names in sorted(self.providers.items())}


def load_plugin(module: ModuleType) -> Commandlet:
    """Instantiate a plugin module via its required `plugin()` factory."""
    return load_plugins(module)[0]


def load_plugins(module: ModuleType) -> tuple[Commandlet, ...]:
    """Instantiate one or more commandlets from a plugin module."""
    multi_factory = getattr(module, "plugins", None)
    if multi_factory is not None:
        plugins = tuple(multi_factory())
        if not plugins:
            raise ValueError(f"{module.__name__}.plugins() returned no commandlets")
        return plugins
    factory = getattr(module, "plugin", None)
    if factory is None:
        raise AttributeError(f"{module.__name__} does not define plugin()")
    return (factory(),)


def load_plugin_path(path: Path) -> Commandlet:
    """Load an external plugin module from a concrete Python file path."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    module_name = f"bywaf_external_{path.parent.name}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return load_plugin(module)


def load_module_defaults(module: ModuleType, plugin: Commandlet, varstore: VarStore) -> None:
    """Import module-level DEFAULTS into the shared VarStore."""
    defaults = getattr(module, "DEFAULTS", None)
    if isinstance(defaults, dict):
        varstore.update_prefixed(plugin.spec.name, defaults)


def load_defaults_file(path: Path, plugin: Commandlet, varstore: VarStore) -> None:
    """Load filesystem plugin defaults from JSON when present."""
    if path.exists():
        values = json.loads(path.read_text())
        if not isinstance(values, dict):
            raise ValueError(f"{path} must contain a JSON object")
        varstore.update_prefixed(plugin.spec.name, values)


def parse_plugin_config(path: Path) -> list[str]:
    """Parse JSON or minimal YAML-style plugin config files."""
    text = path.read_text()
    if path.suffix == ".json":
        data: Any = json.loads(text)
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
    text = config.read_text()
    data: Any = json.loads(text)
    return list(data.get("default_plugins", []))


def provider_name(entry: str) -> str:
    """Derive provider name from a dotted plugin config entry."""
    return entry.split(".", 1)[0] if "." in entry else entry
