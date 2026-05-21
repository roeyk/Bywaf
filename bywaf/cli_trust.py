"""CLI-facing plugin trust and catalog loading helpers."""

from __future__ import annotations

import argparse
from pathlib import Path

from .db import EventStore
from .registry import (
    PluginRegistry,
    PluginTrustError,
    PluginTrustPolicy,
    load_verified_plugin_catalog,
    parse_plugin_config,
)
from .triggers import trigger_action_name
from .varstore import VarStore


def plugin_trust_policy_from_args(args: argparse.Namespace) -> PluginTrustPolicy:
    """Return explicit plugin trust bypasses selected on the CLI."""
    if args.force_plugins:
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
    catalog = None
    if plugin_catalog is not None:
        try:
            catalog = load_verified_plugin_catalog(
                plugin_catalog,
                plugin_catalog_key,
                trust_policy=plugin_trust_policy,
            )
        except PluginTrustError as exc:
            db.publish(
                "plugin.catalog.rejected",
                plugin_catalog_payload(plugin_catalog, plugin_catalog_key, reason=str(exc)),
                "framework",
            )
            raise
        db.publish(
            "plugin.catalog.verified",
            plugin_catalog_payload(
                plugin_catalog,
                plugin_catalog_key,
                verified_signature=catalog.verified_signature,
                entries=len(catalog.plugins),
            ),
            "framework",
        )
    registry = PluginRegistry({}, varstore)
    policy = PluginTrustPolicy.developer_bypass() if forced_plugins else plugin_trust_policy
    for entry in parse_plugin_config(plugin_config):
        plugin_dir = plugin_root / entry
        catalog_entry_verified = False
        if catalog is not None:
            if catalog.verifies_entry(plugin_dir, entry):
                catalog_entry_verified = True
                db.publish(
                    "plugin.catalog.entry.verified",
                    plugin_catalog_entry_payload(catalog.path, plugin_dir, entry),
                    "framework",
                )
            else:
                db.publish(
                    "plugin.catalog.entry.rejected",
                    plugin_catalog_entry_payload(catalog.path, plugin_dir, entry, reason="catalog entry missing or hash mismatch"),
                    "framework",
                )
                raise PluginTrustError(f"warning: refusing external plugin {plugin_dir}; catalog entry missing or hash mismatch")
        try:
            registry.load_filesystem_entry(plugin_root, entry, trust_policy=policy, catalog=catalog, manifest_key=plugin_manifest_key)
        except PluginTrustError as exc:
            if not catalog_entry_verified:
                db.publish(
                    "plugin.manifest.rejected",
                    plugin_manifest_payload(plugin_dir / "bywaf.plugin.toml", plugin_manifest_key, entry, reason=str(exc)),
                    "framework",
                )
            raise
        if plugin_manifest_key is not None and not catalog_entry_verified and not (policy and policy.allow_unsigned_plugin_manifests):
            db.publish(
                "plugin.manifest.verified",
                plugin_manifest_payload(plugin_dir / "bywaf.plugin.toml", plugin_manifest_key, entry),
                "framework",
            )
    return registry


def merge_filesystem_registry(registry: PluginRegistry, filesystem: PluginRegistry) -> None:
    """Merge loaded filesystem plugin providers and triggers into a registry."""
    registry.plugins.update(filesystem.plugins)
    for provider, commandlets in filesystem.providers.items():
        registry.providers.setdefault(provider, []).extend(commandlets)
    for trigger in filesystem.triggers:
        provider = filesystem.trigger_provider(trigger) or trigger_action_name(trigger)
        registry.add_triggers(provider, (trigger,))


def plugin_catalog_payload(
    catalog: Path,
    public_key: Path | None,
    *,
    reason: str | None = None,
    verified_signature: bool | None = None,
    entries: int | None = None,
) -> dict[str, object]:
    """Return audit payload for catalog-level trust events."""
    payload: dict[str, object] = {
        "catalog": str(catalog),
        "public_key": str(public_key) if public_key is not None else None,
    }
    if reason is not None:
        payload["reason"] = reason
    if verified_signature is not None:
        payload["verified_signature"] = verified_signature
    if entries is not None:
        payload["entries"] = entries
    return payload


def plugin_catalog_entry_payload(
    catalog: Path,
    plugin_dir: Path,
    entry: str,
    *,
    reason: str | None = None,
) -> dict[str, object]:
    """Return audit payload for plugin-catalog entry trust events."""
    payload: dict[str, object] = {
        "catalog": str(catalog),
        "entry": entry,
        "plugin": str(plugin_dir),
        "module": str(plugin_dir / "plugin.py"),
        "manifest": str(plugin_dir / "bywaf.plugin.toml"),
    }
    if reason is not None:
        payload["reason"] = reason
    return payload


def plugin_manifest_payload(
    manifest: Path,
    public_key: Path | None,
    entry: str,
    *,
    reason: str | None = None,
) -> dict[str, object]:
    """Return audit payload for manifest-level trust events."""
    payload: dict[str, object] = {
        "entry": entry,
        "manifest": str(manifest),
        "public_key": str(public_key) if public_key is not None else None,
    }
    if reason is not None:
        payload["reason"] = reason
    return payload
