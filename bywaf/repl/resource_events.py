"""Audit helpers for explicitly loaded REPL resources.

Provides resource-loaded audit event publication and plugin manifest metadata
capture for resource load operations.

Used by:
- resource facade: audit filesystem plugin loads.
- script execution: audit loaded script files and command counts.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..events import Event
from ..registry import parse_plugin_manifest
from ..runner import Runner, new_run_id


def publish_resource_loaded(
    runner: Runner,
    resource_type: str,
    *,
    path: Path,
    details: dict[str, object] | None = None,
) -> Event:
    """Audit one explicitly loaded resource and return the persisted event."""
    serial = new_run_id(resource_type)
    # Resource loads are not commandlet steps, but they still need stable
    # serials so history and audit views can cite them later.
    payload: dict[str, object] = {
        "serial": serial,
        "resource_type": resource_type,
        "path": str(path),
    }
    if details:
        payload.update(details)
    return runner.events.publish(f"resource.{resource_type}.loaded", payload, "framework")


def plugin_manifest_audit_details(plugin_path: Path) -> dict[str, object]:
    """Return manifest metadata for plugin-load audit events."""
    manifest_path = plugin_path / "bywaf.plugin.toml"
    if not manifest_path.exists():
        return {"manifest": None, "manifest_sha256": None}
    manifest = parse_plugin_manifest(manifest_path)
    # Capture manifest claims without importing the plugin. This keeps load
    # audit cheap and preserves exactly what trust validation saw.
    return {
        "manifest": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "traits": {
            "native": manifest.native,
            "library_backed": manifest.library_backed,
            "process_wrapped": manifest.process_wrapped,
            "service": manifest.service,
        },
        "roles": list(manifest.roles),
        "capabilities": {
            name: list(capabilities)
            for name, capabilities in sorted(manifest.commandlet_capabilities.items())
        },
        "secret_options": {
            name: list(options)
            for name, options in sorted(manifest.commandlet_secret_options.items())
            if options
        },
    }


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash for one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        # Stream large manifests/resources instead of reading whole files into
        # memory. Manifests are small today, but this helper is generic.
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
