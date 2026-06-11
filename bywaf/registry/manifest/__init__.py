"""Plugin manifest parsing and code/manifest drift checks.

Provides `PluginManifest`, TOML parsing helpers, trigger metadata parsing,
filesystem package loading, and commandlet/trigger manifest enforcement.

Used by:
- registry.core: validates bundled and filesystem providers.
- REPL resource events and plugin tooling: inspect plugin manifest metadata."""

from __future__ import annotations

import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

from ...event.schemas import register_event_schemas
from ...plugin import Commandlet
from ...specs import TriggerSpec
from ...toml_support import load_data_file
from ..loading import load_module_path, load_plugins, load_trigger_specs
from ..trust import (
    PluginTrustPolicy,
)
from ..trust_manifest import (
    PluginManifestTrust,
    enforce_manifest_sig,
)
from .commandlets import parse_manifest_commandlets
from .enforcement import enforce_plugin_manifest, enforce_trigger_manifest
from .fields import (
    bool_field,
    list_field as list_field,
    optional_string_field,
    require_known_keys,
    string_field as string_field,
    string_list_field,
    table_value,
    validate_requires_bywaf,
    validate_version_string,
)
from .model import PluginManifest
from .schemas import parse_event_schema_rows
from .triggers import parse_trigger_rows


def load_filesystem_plugins(plugin_dir: Path) -> tuple[Commandlet, ...]:
    """Load a filesystem plugin package and enforce its required manifest."""
    return load_filesystem_plugin_package(plugin_dir)[0]


def load_filesystem_plugin_package(
    plugin_dir: Path,
    *,
    trust_policy: PluginTrustPolicy | None = None,
    manifest_trust: PluginManifestTrust | None = None,
) -> tuple[tuple[Commandlet, ...], tuple[TriggerSpec, ...], PluginManifest]:
    """Load filesystem commandlets and provider-owned trigger specs."""
    manifest_path = plugin_dir / "bywaf.plugin.toml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"{manifest_path} not found")
    enforce_manifest_sig(manifest_path, trust_policy=trust_policy, manifest_trust=manifest_trust)
    manifest = parse_plugin_manifest(manifest_path)
    module = load_module_path(plugin_dir / "plugin.py")
    plugins = enforce_plugin_manifest(manifest, load_plugins(module), manifest_path)
    triggers = enforce_trigger_manifest(manifest, load_trigger_specs(module), manifest_path)
    register_event_schemas(manifest.event_schemas)
    return plugins, triggers, manifest


def parse_plugin_manifest(path: Path) -> PluginManifest:
    """Parse and validate a filesystem plugin manifest."""
    return parse_plugin_manifest_data(load_data_file(path), str(path))


def parse_plugin_manifest_data(data: dict[str, Any], source: str) -> PluginManifest:
    """Parse and validate plugin manifest data from TOML.

    The manifest is intentionally stricter than plugin.py metadata alone.  It
    lets Bywaf inspect plugin shape before import, enforce declared
    capabilities after import, and expose catalog variables for unloaded
    plugins.
    """
    plugin_data = table_value(data, "plugin", source)
    require_known_keys(data, {"plugin", "commandlets", "event_schemas", "triggers", "bywaf_signature"}, source, "manifest")
    require_known_keys(
        plugin_data,
        {
            "version",
            "requires_bywaf",
            "requires_schemas",
            "requires_plugins",
            "native",
            "library_backed",
            "process_wrapped",
            "service",
            "roles",
            "default_commandlet",
        },
        source,
        "plugin",
    )
    version = optional_string_field(plugin_data, "version", source, "plugin", default="0.0.0") or "0.0.0"
    validate_version_string(version, source, "plugin.version")
    requires_bywaf = optional_string_field(plugin_data, "requires_bywaf", source, "plugin")
    if requires_bywaf is not None:
        validate_requires_bywaf(requires_bywaf, source, "plugin.requires_bywaf")
    requires_schemas = string_list_field(plugin_data, "requires_schemas", source, "plugin")
    requires_plugins = string_list_field(plugin_data, "requires_plugins", source, "plugin")
    # Commandlets are normalized into parallel maps keyed by commandlet name.
    # That keeps later manifest/code enforcement simple: each contract surface
    # can be compared independently without reparsing the raw TOML rows.
    commandlets = parse_manifest_commandlets(data.get("commandlets"), source)
    library_backed = bool_field(plugin_data, "library_backed", source, "plugin")
    process_wrapped = bool_field(plugin_data, "process_wrapped", source, "plugin")
    service = bool_field(plugin_data, "service", source, "plugin")
    native = bool_field(plugin_data, "native", source, "plugin")
    # `native` means the plugin is pure in-process Python.  Library-backed and
    # process-wrapped plugins are still Python plugins, but they carry extra
    # dependency/process implications and should not also be marked native.
    if native and (library_backed or process_wrapped):
        raise ValueError(f"{source} native=true conflicts with library_backed or process_wrapped")
    roles = string_list_field(plugin_data, "roles", source, "plugin")
    default_commandlet = optional_string_field(plugin_data, "default_commandlet", source, "plugin")
    if default_commandlet is not None and default_commandlet not in commandlets.names:
        raise ValueError(f"{source} plugin.default_commandlet must name a declared commandlet")
    # Triggers and event schemas are parsed after commandlets because they are
    # provider-level declarations, not per-commandlet metadata.
    triggers = parse_trigger_rows(data.get("triggers", []), source)
    event_schemas = parse_event_schema_rows(data.get("event_schemas", []), source)
    return PluginManifest(
        commandlets=commandlets.names,
        version=version,
        requires_bywaf=requires_bywaf,
        requires_schemas=requires_schemas,
        requires_plugins=requires_plugins,
        triggers=triggers,
        commandlet_capabilities=commandlets.capabilities,
        commandlet_database_actions=commandlets.database_actions,
        commandlet_consumes=commandlets.consumes,
        commandlet_emits=commandlets.emits,
        commandlet_options=commandlets.options,
        commandlet_arguments=commandlets.arguments,
        commandlet_secret_options=commandlets.secret_options,
        commandlet_provider_variables=commandlets.provider_variables,
        commandlet_secret_vars=commandlets.secret_provider_variables,
        event_schemas=event_schemas,
        default_commandlet=default_commandlet,
        library_backed=library_backed,
        process_wrapped=process_wrapped,
        service=service,
        native=native or not (library_backed or process_wrapped),
        roles=roles,
    )


def load_package_manifest(package_name: str, entry: str) -> PluginManifest | None:
    """Load a bundled sidecar manifest before importing plugin code."""
    parts = entry.split(".")
    package_local = resources.files(package_name)
    for part in (*parts, "bywaf.plugin.toml"):
        package_local = package_local.joinpath(part)
    if package_local.is_file():
        data = tomllib.loads(package_local.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{package_local} must contain TOML tables")
        return parse_plugin_manifest_data(data, str(package_local))
    manifest = resources.files(package_name)
    for part in (*parts[:-1], f"{parts[-1]}.plugin.toml"):
        manifest = manifest.joinpath(part)
    if not manifest.is_file():
        return None
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{manifest} must contain TOML tables")
    return parse_plugin_manifest_data(data, str(manifest))
