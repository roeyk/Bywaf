"""PluginRegistry loading and discovery behavior.

Used by:
- `PluginRegistry.discover()`: load bundled plugin providers.
- `PluginRegistry.from_config()`: load filesystem plugin providers and their
  dependency closure before importing plugin code.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..event.schemas import register_event_schemas
from ..plugin import Commandlet
from .config import (
    load_defaults_file,
    load_module_defaults,
    normalize_catalog_path,
    parse_package_plugin_aliases,
    parse_package_plugin_config,
    parse_plugin_config,
)
from .dependencies import fs_manifest_dep_closure
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
    PluginTrustPolicy,
    VerifiedPluginCatalog,
    enforce_filesystem_plugin_trust,
)
from .trust_manifest import PluginManifestTrust

if TYPE_CHECKING:
    from ..varstore import VarStore


class PluginRegistryLoadingMixin:
    """Loading helpers mixed into `PluginRegistry`.

    The mixin owns pre-import manifest/trust/dependency handling. The concrete
    registry class owns the in-memory catalog fields and lookup APIs.
    """

    @classmethod
    def discover(
        cls,
        package_name: str = "bywaf.plugins",
        *,
        config_name: str = "plugins.toml",
        varstore: VarStore | None = None,
    ):
        """Load bundled plugins from a package-level config file."""
        entries = parse_package_plugin_config(package_name, config_name)
        registry_cls = cast(Any, cls)
        store = varstore or registry_cls.varstore_class()
        registry = registry_cls({}, store)
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
    ):
        """Load plugins from an explicit filesystem config file."""
        registry_cls = cast(Any, cls)
        registry = registry_cls({}, varstore or registry_cls.varstore_class())
        entries = parse_plugin_config(Path(config_file))
        plugin_root = Path(plugin_root)
        requested_entries = tuple(normalize_catalog_path(entry) for entry in entries)
        entries, filesystem_manifests = fs_manifest_dep_closure(plugin_root, entries)
        load_order = tuple(normalize_catalog_path(entry) for entry in entries)
        requested_set = set(requested_entries)
        auto_loaded = tuple(provider for provider in load_order if provider not in requested_set)
        registry.filesystem_requested_providers = requested_entries
        registry.filesystem_load_order = load_order
        registry.fs_autoloaded_providers = auto_loaded
        registry.filesystem_auto_load_reasons = {provider: "requires_plugins" for provider in auto_loaded}
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
                trust_policy=PluginTrustPolicy.developer_bypass() if forced else trust_policy,
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
        their catalog/provider path. Local development may remap the catalog
        path, but a verified catalog entry must keep the signed path binding so
        untrusted config cannot present a plugin under a misleading namespace.
        """
        registry = cast(Any, self)
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
        graph = build_manifest_graph({**bundled_manifest_map(), **registry.manifests, provider_path: pre_import_manifest})
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
            registry.register_commandlet(
                provider_path,
                plugin,
                origin="filesystem",
                plugin_version=manifest.version,
                requires_bywaf=manifest.requires_bywaf,
            )
            load_defaults_file(plugin_dir, plugin, registry.varstore, scope=registry.variable_scope(plugin.spec.name))
        registry.register_provider_default(provider_path, manifest.default_commandlet)
        registry.add_triggers(entry, triggers)
        registry.manifests[provider_path] = manifest
        return plugins[0]

    def load_package_entry(self, package_name: str, entry: str) -> Commandlet:
        """Load one bundled plugin module by dotted entry name.

        Bundled plugins are trusted code, but their manifests still matter:
        they keep capabilities, triggers, and provider defaults inspectable and
        catch drift between declared plugin metadata and runtime objects.
        """
        registry = cast(Any, self)
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
            registry.register_commandlet(
                provider_path,
                plugin,
                origin="bundled",
                plugin_version=manifest.version if manifest is not None else "0.0.0",
                requires_bywaf=manifest.requires_bywaf if manifest is not None else None,
            )
            load_module_defaults(module, plugin, registry.varstore, scope=registry.variable_scope(plugin.spec.name))
        if manifest is not None:
            registry.register_provider_default(provider_path, manifest.default_commandlet)
            registry.manifests[provider_path] = manifest
        registry.add_triggers(entry, triggers)
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
