"""Runtime plugin registry.

Provides `PluginRegistry`, the loaded commandlet/provider/trigger index used by
the runner, completion layer, REPL, and API.

Used by:
- CLI startup and API sessions: construct command registries.
- runner and completion: resolve commandlets, providers, and trigger identity."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path

from ..plugin import Commandlet
from ..secrets import InMemorySecretStore
from ..specs import TriggerSpec
from ..varstore import VarStore
from .config import load_defaults_file, load_module_defaults, normalize_catalog_path, parse_package_plugin_config, parse_plugin_config, provider_name
from .loading import load_plugins, load_trigger_specs
from .manifest import (
    enforce_plugin_manifest,
    enforce_trigger_manifest,
    load_filesystem_plugin_package,
    load_package_manifest,
)
from .trust import (
    PluginManifestTrust,
    PluginTrustPolicy,
    VerifiedPluginCatalog,
    enforce_filesystem_plugin_trust,
)


@dataclass(slots=True)
class PluginRegistry:
    """Loaded commandlets plus their provider grouping and shared variables."""

    plugins: dict[str, Commandlet]
    varstore: VarStore = field(default_factory=VarStore)
    providers: dict[str, list[str]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    primary_aliases: dict[str, str] = field(default_factory=dict)
    provider_commandlets: dict[str, list[str]] = field(default_factory=dict)
    provider_defaults: dict[str, str] = field(default_factory=dict)
    secrets: InMemorySecretStore = field(default_factory=InMemorySecretStore)
    triggers: list[TriggerSpec] = field(default_factory=list)
    trigger_providers: dict[int, str] = field(default_factory=dict)

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
        forced: bool = False,
        trust_policy: PluginTrustPolicy | None = None,
        catalog: VerifiedPluginCatalog | None = None,
    ) -> "PluginRegistry":
        """Load plugins from an explicit filesystem config file."""
        registry = cls({}, varstore or VarStore())
        policy = PluginTrustPolicy.developer_bypass() if forced else trust_policy
        for entry in parse_plugin_config(Path(config_file)):
            registry.load_filesystem_entry(Path(plugin_root), entry, trust_policy=policy, catalog=catalog)
        return registry

    def load_filesystem_entry(
        self,
        plugin_root: Path,
        entry: str,
        *,
        catalog_path: str | None = None,
        forced: bool = False,
        trust_policy: PluginTrustPolicy | None = None,
        catalog: VerifiedPluginCatalog | None = None,
        manifest_key: Path | None = None,
    ) -> Commandlet:
        """Load commandlets from `<plugin_root>/<entry>`, enforcing its manifest."""
        plugin_dir = plugin_root / entry
        provider_path = normalize_catalog_path(catalog_path or entry)
        policy = PluginTrustPolicy.developer_bypass() if forced else trust_policy
        if catalog_path and catalog is not None and catalog.verifies_entry(plugin_dir, entry):
            raise ValueError("catalog-verified plugin paths cannot be remapped with path=")
        enforce_filesystem_plugin_trust(plugin_dir, entry=entry, trust_policy=policy, catalog=catalog)
        manifest_trust = PluginManifestTrust(
            public_key_path=manifest_key,
            catalog_verified=catalog is not None and catalog.verifies_entry(plugin_dir, entry),
        )
        plugins, triggers, manifest = load_filesystem_plugin_package(plugin_dir, trust_policy=policy, manifest_trust=manifest_trust)
        for plugin in plugins:
            self.register_commandlet(provider_path, plugin)
            load_defaults_file(plugin_dir, plugin, self.varstore, scope=self.variable_scope(plugin.spec.name))
        self.register_provider_default(provider_path, manifest.default_commandlet)
        self.add_triggers(entry, triggers)
        return plugins[0]

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name."""
        manifest = load_package_manifest(package_name, entry)
        provider_path = normalize_catalog_path(entry)
        module = importlib.import_module(f"{package_name}.{entry}")
        plugins = load_plugins(module)
        triggers = load_trigger_specs(module)
        if manifest is not None:
            manifest_path = Path(f"{package_name}.{entry}.plugin.toml")
            plugins = enforce_plugin_manifest(manifest, plugins, manifest_path)
            triggers = enforce_trigger_manifest(manifest, triggers, manifest_path)
        elif triggers:
            raise ValueError(f"{package_name}.{entry} exposes undeclared triggers without a plugin manifest")
        for plugin in plugins:
            self.register_commandlet(provider_path, plugin)
            load_module_defaults(module, plugin, self.varstore, scope=self.variable_scope(plugin.spec.name))
        if manifest is not None:
            self.register_provider_default(provider_path, manifest.default_commandlet)
        self.add_triggers(entry, triggers)
        return plugins[0]

    def register_commandlet(self, entry: str, plugin: Commandlet) -> None:
        """Register one commandlet and its provider-qualified aliases."""
        self.plugins[plugin.spec.name] = plugin
        catalog_path = normalize_catalog_path(entry)
        self.providers.setdefault(provider_name(catalog_path), []).append(plugin.spec.name)
        self.provider_commandlets.setdefault(catalog_path, []).append(plugin.spec.name)
        full_alias = f"{catalog_path}/{plugin.spec.name}"
        self.add_alias(full_alias, plugin.spec.name)
        self.primary_aliases.setdefault(plugin.spec.name, full_alias)
        if catalog_path.rsplit("/", 1)[-1] == plugin.spec.name:
            self.add_alias(catalog_path, plugin.spec.name)
            self.primary_aliases[plugin.spec.name] = catalog_path

    def register_provider_default(self, provider_path: str, default_commandlet: str | None) -> None:
        """Register a provider-local default commandlet for `use <provider>`."""
        if default_commandlet is None:
            return
        if default_commandlet not in self.plugins:
            raise ValueError(f"default commandlet is not loaded: {default_commandlet}")
        self.provider_defaults[normalize_catalog_path(provider_path)] = default_commandlet

    def add_alias(self, alias: str, commandlet: str) -> None:
        """Register one user-facing commandlet alias."""
        if alias == commandlet:
            return
        existing = self.aliases.get(alias)
        if existing is not None and existing != commandlet:
            raise ValueError(f"ambiguous commandlet alias {alias}: {existing}, {commandlet}")
        self.aliases[alias] = commandlet

    def resolve_commandlet_name(self, name: str) -> str:
        """Return the canonical commandlet name for a flat name or alias."""
        return self.aliases.get(name, name)

    def variable_scope(self, name: str) -> str:
        """Return the canonical variable scope for a commandlet name or alias."""
        canonical_name = self.resolve_commandlet_name(name)
        return self.primary_aliases.get(canonical_name, canonical_name)

    def has_commandlet(self, name: str) -> bool:
        """Return whether a flat name or alias resolves to a commandlet."""
        return self.resolve_commandlet_name(name) in self.plugins

    def provider_default(self, provider_path: str) -> str | None:
        """Return the default commandlet for a provider catalog path, if declared."""
        return self.provider_defaults.get(normalize_catalog_path(provider_path))

    def has_provider_path(self, provider_path: str) -> bool:
        """Return whether a provider catalog path is loaded."""
        path = normalize_catalog_path(provider_path)
        return path in self.provider_commandlets or path in self.provider_defaults

    def provider_commandlet_names(self, provider_path: str) -> list[str]:
        """Return commandlets exposed directly by one provider path."""
        return sorted(set(self.provider_commandlets.get(normalize_catalog_path(provider_path), ())))

    def get(self, name: str) -> Commandlet:
        """Return a commandlet by user-facing command name."""
        canonical_name = self.resolve_commandlet_name(name)
        try:
            return self.plugins[canonical_name]
        except KeyError as exc:
            raise KeyError(f"unknown commandlet: {name}") from exc

    def names(self) -> list[str]:
        """Return commandlet names for command completion."""
        return sorted(self.plugins)

    def commandlet_aliases(self) -> list[str]:
        """Return provider-qualified commandlet aliases for completion."""
        return sorted(self.aliases)

    def provider_names(self) -> list[str]:
        """Return provider names for the `plugins` command."""
        return sorted(self.providers)

    def grouped_names(self) -> dict[str, list[str]]:
        """Return commandlets grouped by provider for the `cmds` command."""
        return {provider: sorted(set(names)) for provider, names in sorted(self.providers.items())}

    def add_triggers(self, provider: str, triggers: tuple[TriggerSpec, ...] | list[TriggerSpec]) -> None:
        """Register provider-local trigger specs with framework identity metadata."""
        for trigger in triggers:
            self.triggers.append(trigger)
            self.trigger_providers[id(trigger)] = provider

    def trigger_provider(self, trigger: TriggerSpec) -> str | None:
        """Return the provider identity for one registered trigger."""
        return self.trigger_providers.get(id(trigger))

    def trigger_id(self, trigger: TriggerSpec) -> str:
        """Return the durable framework identity for a provider-owned trigger."""
        provider = self.trigger_provider(trigger)
        if provider is None:
            return trigger.name
        return f"{provider}.{trigger.name}"
