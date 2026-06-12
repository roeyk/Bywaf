"""Filesystem plugin dependency closure and load ordering.

Provides manifest-only dependency expansion for filesystem plugins before any
plugin Python is imported.

Used by:
- `PluginRegistry.from_config()`: auto-load local `requires_plugins`
  dependencies and order them before dependents.
- CLI trust loading: preview filesystem dependency closure before registry
  construction.
"""

from __future__ import annotations

from pathlib import Path

from .config import normalize_catalog_path
from .graph import build_manifest_graph, bundled_manifest_map, provider_in_graph, validate_manifest_dependencies
from .manifest import PluginManifest, parse_plugin_manifest


def fs_manifest_dep_closure(
    plugin_root: Path,
    entries: list[str],
    *,
    base_manifests: dict[str, PluginManifest] | None = None,
) -> tuple[list[str], dict[str, PluginManifest]]:
    """Return configured filesystem entries plus available local dependencies.

    Called by: `PluginRegistry.from_config()` and CLI trust loading.

    The closure phase reads only `bywaf.plugin.toml` metadata. It does not
    import plugin Python. Missing dependencies are left to dependency validation
    so callers receive the same hard-error diagnostics as plugin_check.
    """

    base_manifests = base_manifests or bundled_manifest_map()
    base_graph = build_manifest_graph(base_manifests)
    queue = list(entries)
    manifests: dict[str, PluginManifest] = {}
    provider_entries: dict[str, str] = {}

    # Phase 1: walk the configured provider set and any local dependencies that
    # their manifests explicitly request. This is intentionally manifest-only;
    # plugin code is still untrusted and has not been imported.
    while queue:
        entry = queue.pop(0)
        provider = normalize_catalog_path(entry)
        if provider in manifests:
            continue
        manifest_path = filesystem_manifest_path(plugin_root, entry, provider)
        provider_entries[provider] = provider
        if not manifest_path.exists():
            continue
        manifest = parse_plugin_manifest(manifest_path)
        manifests[provider] = manifest

        # Phase 2: enqueue only dependencies that are available locally and not
        # already satisfied by the bundled manifest graph. Missing local
        # dependencies are not silently ignored; validation below reports them.
        queued_providers = {normalize_catalog_path(item) for item in queue}
        for dependency in manifest.requires_plugins:
            dependency_provider = normalize_catalog_path(dependency)
            if dependency_provider in manifests or dependency_provider in queued_providers:
                continue
            if provider_in_graph(base_graph, dependency_provider):
                continue
            dependency_manifest = plugin_root / dependency_provider / "bywaf.plugin.toml"
            if dependency_manifest.exists():
                queue.append(dependency_provider)

    # Phase 3: validate the complete local chain before loading any plugin code.
    # This ensures A -> B -> missing C fails before A or B is imported.
    graph = build_manifest_graph({**base_manifests, **manifests})
    validate_manifest_dependencies(manifests, graph=graph, providers=manifests)
    return topological_filesystem_entries(entries, manifests, provider_entries), manifests


def filesystem_manifest_path(plugin_root: Path, entry: str, provider: str) -> Path:
    """Return the most likely manifest path for a configured provider.

    Called by: `fs_manifest_dep_closure()`.
    """

    manifest_path = plugin_root / provider / "bywaf.plugin.toml"
    if manifest_path.exists():
        return manifest_path
    return plugin_root / entry / "bywaf.plugin.toml"


def topological_filesystem_entries(
    requested_entries: list[str],
    manifests: dict[str, PluginManifest],
    provider_entries: dict[str, str],
) -> list[str]:
    """Order filesystem entries so required plugins load before dependents.

    Called by: `fs_manifest_dep_closure()`.
    """

    ordered: list[str] = []
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(provider: str) -> None:
        """Visit one node while collecting dependency information."""
        if provider in visited:
            return
        if provider in visiting:
            raise ValueError(f"requires_plugins cycle includes: {provider}")
        visiting.add(provider)
        manifest = manifests[provider]

        # This recursive walk is the topological-sort step: emit dependencies
        # before the provider that requires them, replacing a fragile
        # load-as-configured loop with manifest-derived ordering.
        for dependency in manifest.requires_plugins:
            dependency_provider = normalize_catalog_path(dependency)
            if dependency_provider in manifests:
                visit(dependency_provider)
        visiting.remove(provider)
        visited.add(provider)
        ordered.append(provider_entries[provider])

    # Preserve requested config order for independent providers while still
    # inserting auto-loaded dependencies before each dependent.
    for entry in requested_entries:
        provider = normalize_catalog_path(entry)
        if provider in manifests:
            visit(provider)
        elif provider in provider_entries:
            ordered.append(provider_entries[provider])

    # Include dependencies that were discovered but not reached through a
    # requested provider due to ordering or normalization edge cases.
    for provider in sorted(manifests):
        visit(provider)
    return ordered
