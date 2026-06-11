"""CLI plugin trust and catalog loading helpers.

Provides command-line trust-policy construction plus filesystem plugin catalog
loading, validation, and registry merge behavior.

Used by:
- bywaf.app: applies CLI trust flags before runner construction.
- plugin catalog tests and scripts: verify signed external plugin loading."""


from __future__ import annotations

import argparse
from pathlib import Path

from .db import EventStore
from .plugin_trust_audit import (
    audit_auto_loaded_dependencies,
    load_catalog_with_audit,
    load_entries_with_audit,
    verify_catalog_with_audit,
)
from .registry import (
    PluginRegistry,
    PluginTrustPolicy,
    fs_manifest_dep_closure,
    normalize_catalog_path,
    parse_plugin_config,
)
from .triggers import trigger_action_name
from .varstore import VarStore


def trust_policy_from_args(args: argparse.Namespace) -> PluginTrustPolicy:
    """Return explicit plugin trust bypasses selected on the CLI."""
    if args.force_plugins:
        # --force-plugins is a development escape hatch that skips all plugin
        # trust checks for local iteration.
        return PluginTrustPolicy.developer_bypass()
    if args.allow_untrusted_plugins:
        return PluginTrustPolicy.developer_bypass()
    return PluginTrustPolicy(
        allow_unsigned_plugins=args.allow_unsigned_plugins,
        allow_unsigned_plugin_manifests=args.allow_unsigned_plugin_manifests,
        allow_missing_plugin_keys=args.allow_missing_plugin_keys,
        allow_plugin_key_mismatch=args.allow_mismatched_plugin_keys,
    )


def load_filesystem_registry(
    db: EventStore,
    plugin_root: Path,
    plugin_config: Path,
    *,
    plugin_catalog: Path | None,
    plugin_catalog_key: Path | None,
    plugin_manifest_key: Path | None,
    forced_plugins: bool,
    plugin_trust_policy: PluginTrustPolicy | None,
    varstore: VarStore,
) -> PluginRegistry:
    """Load filesystem plugins and audit catalog trust decisions."""
    catalog = load_catalog_with_audit(db, plugin_catalog, plugin_catalog_key, plugin_trust_policy)
    registry = PluginRegistry({}, varstore)
    policy = PluginTrustPolicy.developer_bypass() if forced_plugins else plugin_trust_policy
    requested_entries = parse_plugin_config(plugin_config)
    entries, filesystem_manifests = fs_manifest_dep_closure(plugin_root, requested_entries)
    requested_providers = tuple(normalize_catalog_path(entry) for entry in requested_entries)
    load_order = tuple(normalize_catalog_path(entry) for entry in entries)
    requested_set = set(requested_providers)
    auto_loaded = tuple(provider for provider in load_order if provider not in requested_set)
    registry.filesystem_requested_providers = requested_providers
    registry.filesystem_load_order = load_order
    registry.fs_autoloaded_providers = auto_loaded
    registry.filesystem_auto_load_reasons = {provider: "requires_plugins" for provider in auto_loaded}
    audit_auto_loaded_dependencies(db, plugin_root, requested_entries, entries)
    verify_catalog_with_audit(db, plugin_root, entries, catalog)
    registry.manifests.update(filesystem_manifests)
    load_entries_with_audit(db, registry, plugin_root, entries, policy, catalog, plugin_manifest_key)
    return registry


def merge_filesystem_registry(registry: PluginRegistry, filesystem: PluginRegistry) -> None:
    """Merge loaded filesystem plugin providers and triggers into a registry."""
    registry.plugins.update(filesystem.plugins)
    registry.aliases.update(filesystem.aliases)
    registry.primary_aliases.update(filesystem.primary_aliases)
    registry.provider_defaults.update(filesystem.provider_defaults)
    registry.commandlet_origins.update(filesystem.commandlet_origins)
    registry.commandlet_plugin_versions.update(filesystem.commandlet_plugin_versions)
    registry.commandlet_bywaf_requirements.update(filesystem.commandlet_bywaf_requirements)
    for provider, commandlets in filesystem.providers.items():
        # Providers can expose multiple commandlets; merge by provider path
        # instead of overwriting the bundled registry's provider table.
        registry.providers.setdefault(provider, []).extend(commandlets)
    for provider_path, commandlets in filesystem.provider_commandlets.items():
        registry.provider_commandlets.setdefault(provider_path, []).extend(commandlets)
    for trigger in filesystem.triggers:
        provider = filesystem.trigger_provider(trigger) or trigger_action_name(trigger)
        registry.add_triggers(provider, (trigger,))
    registry.manifests.update(filesystem.manifests)
    registry.filesystem_requested_providers = filesystem.filesystem_requested_providers
    registry.fs_autoloaded_providers = filesystem.fs_autoloaded_providers
    registry.filesystem_load_order = filesystem.filesystem_load_order
    registry.filesystem_auto_load_reasons.update(filesystem.filesystem_auto_load_reasons)
