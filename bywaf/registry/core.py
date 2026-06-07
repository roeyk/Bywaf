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

from ..event.schemas import register_event_schemas
from ..plugin import Commandlet
from ..secret.store import InMemorySecretStore
from ..specs import TriggerSpec
from ..varstore import VarStore
from .config import (
    load_defaults_file,
    load_module_defaults,
    normalize_catalog_path,
    parse_package_plugin_aliases,
    parse_package_plugin_config,
    parse_plugin_config,
    provider_name,
)
from .graph import build_manifest_graph, bundled_manifest_map, validate_manifest_dependencies
from .loading import load_plugins, load_trigger_specs
from .manifest import (
    PluginManifest,
    enforce_plugin_manifest,
    enforce_trigger_manifest,
    load_filesystem_plugin_package,
    load_package_manifest,
    parse_plugin_manifest,
)
from .trust import (
    PluginManifestTrust,
    PluginTrustPolicy,
    VerifiedPluginCatalog,
    enforce_filesystem_plugin_trust,
)


@dataclass(slots=True)
class PluginRegistry:
    """Loaded commandlets plus their provider grouping and shared variables.

    The registry is the in-memory catalog used by execution, completion, and
    plugin loading.  It keeps flat commandlet names for direct invocation, slash
    aliases for catalog paths, provider defaults for `use <provider>` flows,
    and trigger ownership so durable trigger IDs remain stable.
    """

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
    commandlet_origins: dict[str, str] = field(default_factory=dict)
    commandlet_plugin_versions: dict[str, str] = field(default_factory=dict)
    commandlet_bywaf_requirements: dict[str, str] = field(default_factory=dict)
    manifests: dict[str, PluginManifest] = field(default_factory=dict)

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
        manifests = bundled_manifest_map(package_name, config_name)
        validate_manifest_dependencies(manifests)
        for entry in entries:
            registry.load_package_entry(package_name, entry)
        registry.add_aliases(parse_package_plugin_aliases(package_name, config_name))
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
        entries = parse_plugin_config(Path(config_file))
        plugin_root = Path(plugin_root)
        filesystem_manifests = registry.parse_filesystem_manifest_set(
            plugin_root,
            entries,
            policy=policy,
            catalog=catalog,
        )
        graph = build_manifest_graph({**bundled_manifest_map(), **filesystem_manifests})
        validate_manifest_dependencies(
            filesystem_manifests,
            graph=graph,
            providers=filesystem_manifests,
        )
        for entry in entries:
            registry.load_filesystem_entry(
                plugin_root,
                entry,
                trust_policy=policy,
                catalog=catalog,
            )
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
        """Load commandlets from `<plugin_root>/<entry>`, enforcing its manifest.

        Filesystem plugins have two identities: their on-disk directory and
        their catalog/provider path.  Local development may remap the catalog
        path, but a verified catalog entry must keep the signed path binding so
        untrusted config cannot present a plugin under a misleading namespace.
        """
        plugin_dir = plugin_root / entry
        provider_path = normalize_catalog_path(catalog_path or entry)
        policy = PluginTrustPolicy.developer_bypass() if forced else trust_policy
        if catalog_path and catalog is not None and catalog.verifies_entry(plugin_dir, entry):
            raise ValueError("catalog-verified plugin paths cannot be remapped with path=")

        # Trust enforcement happens before importing plugin.py.  That keeps the
        # manifest/catalog path useful as pre-import metadata rather than only a
        # post-import consistency check.
        enforce_filesystem_plugin_trust(plugin_dir, entry=entry, trust_policy=policy, catalog=catalog)
        pre_import_manifest = parse_plugin_manifest(plugin_dir / "bywaf.plugin.toml")
        graph = build_manifest_graph({**bundled_manifest_map(), **self.manifests, provider_path: pre_import_manifest})
        validate_manifest_dependencies(
            {provider_path: pre_import_manifest},
            graph=graph,
            providers=(provider_path,),
        )
        manifest_trust = PluginManifestTrust(
            public_key_path=manifest_key,
            catalog_verified=catalog is not None and catalog.verifies_entry(plugin_dir, entry),
        )
        plugins, triggers, manifest = load_filesystem_plugin_package(
            plugin_dir,
            trust_policy=policy,
            manifest_trust=manifest_trust,
        )
        for plugin in plugins:
            self.register_commandlet(
                provider_path,
                plugin,
                origin="filesystem",
                plugin_version=manifest.version,
                requires_bywaf=manifest.requires_bywaf,
            )
            load_defaults_file(plugin_dir, plugin, self.varstore, scope=self.variable_scope(plugin.spec.name))
        self.register_provider_default(provider_path, manifest.default_commandlet)
        self.add_triggers(entry, triggers)
        self.manifests[provider_path] = manifest
        return plugins[0]

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name.

        Bundled plugins are trusted code, but their manifests still matter:
        they keep capabilities, triggers, and provider defaults inspectable and
        catch drift between declared plugin metadata and runtime objects.
        """
        manifest = load_package_manifest(package_name, entry)
        provider_path = normalize_catalog_path(entry)
        module = importlib.import_module(f"{package_name}.{entry}")
        plugins = load_plugins(module)
        triggers = load_trigger_specs(module)
        if manifest is not None:
            manifest_path = Path(f"{package_name}.{entry}.plugin.toml")
            plugins = enforce_plugin_manifest(manifest, plugins, manifest_path, hydrate_specs=True)
            triggers = enforce_trigger_manifest(manifest, triggers, manifest_path)
            register_event_schemas(manifest.event_schemas)
        elif triggers:
            raise ValueError(f"{package_name}.{entry} exposes undeclared triggers without a plugin manifest")
        for plugin in plugins:
            self.register_commandlet(
                provider_path,
                plugin,
                origin="bundled",
                plugin_version=manifest.version if manifest is not None else "0.0.0",
                requires_bywaf=manifest.requires_bywaf if manifest is not None else None,
            )
            load_module_defaults(module, plugin, self.varstore, scope=self.variable_scope(plugin.spec.name))
        if manifest is not None:
            self.register_provider_default(provider_path, manifest.default_commandlet)
            self.manifests[provider_path] = manifest
        self.add_triggers(entry, triggers)
        return plugins[0]

    def parse_filesystem_manifest_set(
        self,
        plugin_root: Path,
        entries: list[str],
        *,
        policy: PluginTrustPolicy | None,
        catalog: VerifiedPluginCatalog | None,
    ) -> dict[str, PluginManifest]:
        """Return config-entry manifests after trust checks and before import."""
        manifests = {}
        for entry in entries:
            plugin_dir = plugin_root / entry
            enforce_filesystem_plugin_trust(plugin_dir, entry=entry, trust_policy=policy, catalog=catalog)
            manifests[normalize_catalog_path(entry)] = parse_plugin_manifest(plugin_dir / "bywaf.plugin.toml")
        return manifests

    def register_commandlet(
        self,
        entry: str,
        plugin: Commandlet,
        *,
        origin: str = "bundled",
        plugin_version: str = "0.0.0",
        requires_bywaf: str | None = None,
    ) -> None:
        """Register one commandlet and its provider-qualified aliases."""
        self.plugins[plugin.spec.name] = plugin
        self.commandlet_origins[plugin.spec.name] = origin
        self.commandlet_plugin_versions[plugin.spec.name] = plugin_version
        if requires_bywaf is not None:
            self.commandlet_bywaf_requirements[plugin.spec.name] = requires_bywaf
        catalog_path = normalize_catalog_path(entry)
        self.providers.setdefault(provider_name(catalog_path), []).append(plugin.spec.name)
        self.provider_commandlets.setdefault(catalog_path, []).append(plugin.spec.name)

        # A commandlet can always be called by its flat name, and also by its
        # full catalog path.  If the provider path already ends in the same name
        # as the commandlet, the provider path itself becomes the primary alias
        # for variable scoping and completion display.
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
        if commandlet not in self.plugins:
            raise ValueError(f"alias target is not loaded: {commandlet}")
        existing = self.aliases.get(alias)
        if existing is not None and existing != commandlet:
            raise ValueError(f"ambiguous commandlet alias {alias}: {existing}, {commandlet}")
        self.aliases[alias] = commandlet

    def add_aliases(self, aliases: dict[str, str]) -> None:
        """Register several user-facing commandlet aliases."""
        for alias, commandlet in aliases.items():
            self.add_alias(alias, commandlet)

    def resolve_commandlet_name(self, name: str) -> str:
        """Return the canonical commandlet name for a flat name or alias."""
        return self.aliases.get(name, name)

    def variable_scope(self, name: str) -> str:
        """Return the canonical variable scope for a commandlet name or alias.

        Variables use the commandlet's primary catalog alias when one exists,
        so `set http/repo_exposure/git_expose_check.timeout=5` binds to the
        same commandlet as `git_expose_check` without losing catalog context.
        """
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

    def commandlet_origin(self, name: str) -> str:
        """Return where one commandlet was loaded from."""
        canonical_name = self.resolve_commandlet_name(name)
        return self.commandlet_origins.get(canonical_name, "bundled")

    def commandlet_plugin_version(self, name: str) -> str:
        """Return plugin version for a flat name or alias."""
        canonical_name = self.resolve_commandlet_name(name)
        return self.commandlet_plugin_versions.get(canonical_name, "0.0.0")

    def commandlet_requires_bywaf(self, name: str) -> str | None:
        """Return framework version requirement for a flat name or alias."""
        canonical_name = self.resolve_commandlet_name(name)
        return self.commandlet_bywaf_requirements.get(canonical_name)

    def names(self) -> list[str]:
        """Return commandlet names for command completion."""
        return sorted(self.plugins)

    def commandlet_aliases(self) -> list[str]:
        """Return user-facing commandlet aliases for completion."""
        return sorted(self.aliases)

    def commandlet_aliases_for(self, name: str, *, include_provider: bool = True) -> list[str]:
        """Return aliases that resolve to one canonical commandlet."""
        canonical_name = self.resolve_commandlet_name(name)
        aliases = [
            alias
            for alias, commandlet in self.aliases.items()
            if commandlet == canonical_name and (include_provider or "/" not in alias)
        ]
        return sorted(aliases)

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
