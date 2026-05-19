"""Plugin discovery."""

from __future__ import annotations

import importlib
import importlib.util
import json
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

from .plugin import Commandlet
from .secrets import InMemorySecretStore
from .toml_support import load_data_file
from .varstore import VarStore


@dataclass(slots=True)
class PluginRegistry:
    """Loaded commandlets plus their provider grouping and shared variables."""

    plugins: dict[str, Commandlet]
    varstore: VarStore = field(default_factory=VarStore)
    providers: dict[str, list[str]] = field(default_factory=dict)
    secrets: InMemorySecretStore = field(default_factory=InMemorySecretStore)

    @classmethod
    def discover(
        cls,
        package_name: str = "bywaf.plugins",
        *,
        config_name: str = "plugins.toml",
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
        """Load commandlets from `<plugin_root>/<entry>`, enforcing its manifest."""
        plugin_dir = plugin_root / entry
        plugins = load_filesystem_plugins(plugin_dir)
        for plugin in plugins:
            self.plugins[plugin.spec.name] = plugin
            self.providers.setdefault(provider_name(entry), []).append(plugin.spec.name)
            load_defaults_file(plugin_dir, plugin, self.varstore)
        return plugins[0]

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name."""
        manifest = load_package_manifest(package_name, entry)
        module = importlib.import_module(f"{package_name}.{entry}")
        plugins = load_plugins(module)
        if manifest is not None:
            plugins = enforce_plugin_manifest(manifest, plugins, Path(f"{package_name}.{entry}.plugin.toml"))
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
    return load_plugins_path(path)[0]


def load_plugins_path(path: Path) -> tuple[Commandlet, ...]:
    """Load external commandlets from a concrete Python file path."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    module_name = f"bywaf_external_{path.parent.name}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return load_plugins(module)


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Pre-import metadata that controls filesystem plugin exposure."""

    commandlets: frozenset[str]
    commandlet_capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    library_backed: bool = False
    process_wrapped: bool = False
    service: bool = False
    native: bool = False
    roles: tuple[str, ...] = ()


def load_filesystem_plugins(plugin_dir: Path) -> tuple[Commandlet, ...]:
    """Load a filesystem plugin package and enforce `bywaf.plugin.toml` if present."""
    plugins = load_plugins_path(plugin_dir / "plugin.py")
    manifest_path = plugin_dir / "bywaf.plugin.toml"
    if not manifest_path.exists():
        return plugins
    return enforce_plugin_manifest(parse_plugin_manifest(manifest_path), plugins, manifest_path)


def parse_plugin_manifest(path: Path) -> PluginManifest:
    """Parse and validate a filesystem plugin manifest."""
    return parse_plugin_manifest_data(load_data_file(path), str(path))


def parse_plugin_manifest_data(data: dict[str, Any], source: str) -> PluginManifest:
    """Parse and validate plugin manifest data from TOML."""
    plugin_data = table_value(data, "plugin", source)
    commandlet_rows = data.get("commandlets")
    if not isinstance(commandlet_rows, list) or not commandlet_rows:
        raise ValueError(f"{source} must declare at least one [[commandlets]] entry")
    commandlets: set[str] = set()
    commandlet_capabilities: dict[str, tuple[str, ...]] = {}
    commandlet_secret_options: dict[str, tuple[str, ...]] = {}
    for index, row in enumerate(commandlet_rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} commandlets entry {index} must be a table")
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{source} commandlets entry {index} requires name")
        commandlets.add(name)
        commandlet_capabilities[name] = tuple(str(value) for value in list_field(row, "capabilities", source))
        commandlet_secret_options[name] = tuple(str(value) for value in list_field(row, "secret_options", source))
    library_backed = bool_field(plugin_data, "library_backed", source)
    process_wrapped = bool_field(plugin_data, "process_wrapped", source)
    service = bool_field(plugin_data, "service", source)
    native = bool_field(plugin_data, "native", source)
    if native and (library_backed or process_wrapped):
        raise ValueError(f"{source} native=true conflicts with library_backed or process_wrapped")
    roles = tuple(str(role) for role in list_field(plugin_data, "roles", source))
    return PluginManifest(
        commandlets=frozenset(commandlets),
        commandlet_capabilities=commandlet_capabilities,
        commandlet_secret_options=commandlet_secret_options,
        library_backed=library_backed,
        process_wrapped=process_wrapped,
        service=service,
        native=native or not (library_backed or process_wrapped),
        roles=roles,
    )


def enforce_plugin_manifest(
    manifest: PluginManifest,
    plugins: tuple[Commandlet, ...],
    path: Path,
) -> tuple[Commandlet, ...]:
    """Return only manifest-declared commandlets and reject missing declarations."""
    by_name = {plugin.spec.name: plugin for plugin in plugins}
    missing = sorted(manifest.commandlets.difference(by_name))
    if missing:
        raise ValueError(f"{path} declares missing commandlets: {', '.join(missing)}")
    for name in sorted(manifest.commandlets):
        manifest_caps = set(manifest.commandlet_capabilities.get(name, ()))
        code_caps = set(by_name[name].spec.capabilities)
        if manifest_caps != code_caps:
            missing_caps = sorted(code_caps.difference(manifest_caps))
            stale_caps = sorted(manifest_caps.difference(code_caps))
            details = []
            if missing_caps:
                details.append(f"missing {', '.join(missing_caps)}")
            if stale_caps:
                details.append(f"stale {', '.join(stale_caps)}")
            raise ValueError(f"{path} capabilities mismatch for {name}: {'; '.join(details)}")
        manifest_secret_options = set(manifest.commandlet_secret_options.get(name, ()))
        code_secret_options = {option.name for option in by_name[name].spec.options if option.secret}
        if manifest_secret_options != code_secret_options:
            missing_options = sorted(code_secret_options.difference(manifest_secret_options))
            stale_options = sorted(manifest_secret_options.difference(code_secret_options))
            details = []
            if missing_options:
                details.append(f"missing {', '.join(missing_options)}")
            if stale_options:
                details.append(f"stale {', '.join(stale_options)}")
            raise ValueError(f"{path} secret_options mismatch for {name}: {'; '.join(details)}")
    return tuple(by_name[name] for name in sorted(manifest.commandlets))


def load_package_manifest(package_name: str, entry: str) -> PluginManifest | None:
    """Load a bundled sidecar manifest before importing plugin code."""
    parts = entry.split(".")
    manifest = resources.files(package_name)
    for part in (*parts[:-1], f"{parts[-1]}.plugin.toml"):
        manifest = manifest.joinpath(part)
    if not manifest.is_file():
        return None
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{manifest} must contain TOML tables")
    return parse_plugin_manifest_data(data, str(manifest))


def table_value(data: dict[str, Any], key: str, source: str) -> dict[str, Any]:
    """Return one TOML table from a manifest."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{source} [{key}] must be a table")
    return value


def bool_field(data: dict[str, Any], key: str, source: str) -> bool:
    """Return a boolean manifest field."""
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{source} plugin.{key} must be true or false")
    return value


def list_field(data: dict[str, Any], key: str, source: str) -> list[Any]:
    """Return a list manifest field."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} plugin.{key} must be a list")
    return value


def load_module_defaults(module: ModuleType, plugin: Commandlet, varstore: VarStore) -> None:
    """Import module-level DEFAULTS into the shared VarStore."""
    defaults = getattr(module, "DEFAULTS", None)
    if isinstance(defaults, dict):
        varstore.update_prefixed(plugin.spec.name, defaults)


def load_defaults_file(plugin_dir: Path, plugin: Commandlet, varstore: VarStore) -> None:
    """Load filesystem plugin defaults from TOML, with JSON compatibility."""
    path = first_existing(plugin_dir / "defaults.toml", plugin_dir / "defaults.json")
    if path is None:
        return
    values = load_data_file(path)
    varstore.update_prefixed(plugin.spec.name, values.get("defaults", values))


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
