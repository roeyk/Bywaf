"""Plugin trust audit helpers.

Provides audit-event publishing and payload construction for filesystem plugin
catalog and manifest trust decisions.

Used by:
- cli_trust: keep CLI plugin loading focused on orchestration while preserving
  trust/audit event ordering and payload shapes."""

from __future__ import annotations

from pathlib import Path

from .db import EventStore
from .registry import PluginRegistry, PluginTrustError, PluginTrustPolicy, VerifiedPluginCatalog, load_verified_plugin_catalog


def load_catalog_with_audit(
    db: EventStore,
    plugin_catalog: Path | None,
    plugin_catalog_key: Path | None,
    plugin_trust_policy: PluginTrustPolicy | None,
) -> VerifiedPluginCatalog | None:
    """Load a signed plugin catalog and publish catalog-level audit events."""
    if plugin_catalog is None:
        return None
    try:
        # Catalog verification happens before loading individual plugin modules
        # so trust decisions do not execute plugin code first.
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
    return catalog


def audit_auto_loaded_dependencies(
    db: EventStore,
    plugin_root: Path,
    requested_entries: list[str],
    entries: list[str],
) -> None:
    """Publish audit events for dependency providers added to the load set."""
    requested_providers = {entry.replace(".", "/") for entry in requested_entries}
    for entry in entries:
        provider = entry.replace(".", "/")
        if provider in requested_providers:
            continue
        db.publish(
            "plugin.dependency.auto_loaded",
            {"plugin": provider, "reason": "requires_plugins", "plugin_root": str(plugin_root)},
            "framework",
        )


def verify_catalog_with_audit(
    db: EventStore,
    plugin_root: Path,
    entries: list[str],
    catalog: VerifiedPluginCatalog | None,
) -> None:
    """Verify configured catalog entries and publish per-entry audit events."""
    if catalog is None:
        return
    for entry in entries:
        plugin_dir = plugin_root / entry
        # A signed catalog binds entry name to plugin directory contents.
        # Manual path overrides are intentionally outside this path.
        if catalog.verifies_entry(plugin_dir, entry):
            db.publish(
                "plugin.catalog.entry.verified",
                plugin_catalog_entry_payload(catalog.path, plugin_dir, entry),
                "framework",
            )
            continue
        db.publish(
            "plugin.catalog.entry.rejected",
            plugin_catalog_entry_payload(catalog.path, plugin_dir, entry, reason="catalog entry missing or hash mismatch"),
            "framework",
        )
        raise PluginTrustError(f"warning: refusing external plugin {plugin_dir}; catalog entry missing or hash mismatch")


def load_entries_with_audit(
    db: EventStore,
    registry: PluginRegistry,
    plugin_root: Path,
    entries: list[str],
    policy: PluginTrustPolicy | None,
    catalog: VerifiedPluginCatalog | None,
    plugin_manifest_key: Path | None,
) -> None:
    """Load filesystem entries and publish manifest-level audit events."""
    for entry in entries:
        plugin_dir = plugin_root / entry
        catalog_entry_verified = catalog is not None and catalog.verifies_entry(plugin_dir, entry)
        try:
            # Manifest trust is checked by the registry loader. This wrapper
            # adds CLI/audit context around success or rejection.
            registry.load_filesystem_entry(plugin_root, entry, trust_policy=policy, catalog=catalog, manifest_key=plugin_manifest_key)
        except PluginTrustError as exc:
            if not catalog_entry_verified:
                db.publish(
                    "plugin.manifest.rejected",
                    plugin_manifest_payload(plugin_dir / "bywaf.plugin.toml", plugin_manifest_key, entry, reason=str(exc)),
                    "framework",
                )
            raise
        if should_audit_manifest_verified(plugin_manifest_key, catalog_entry_verified, policy):
            db.publish(
                "plugin.manifest.verified",
                plugin_manifest_payload(plugin_dir / "bywaf.plugin.toml", plugin_manifest_key, entry),
                "framework",
            )


def should_audit_manifest_verified(
    plugin_manifest_key: Path | None,
    catalog_entry_verified: bool,
    policy: PluginTrustPolicy | None,
) -> bool:
    """Return whether a manifest verification success audit event is needed."""
    if plugin_manifest_key is None or catalog_entry_verified:
        return False
    return not (policy and policy.allow_unsigned_plugin_manifests)


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
