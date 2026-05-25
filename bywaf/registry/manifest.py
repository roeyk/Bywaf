"""Plugin manifest parsing and code/manifest drift checks.

Provides `PluginManifest`, TOML parsing helpers, trigger metadata parsing,
filesystem package loading, and commandlet/trigger manifest enforcement.

Used by:
- registry.core: validates bundled and filesystem providers.
- REPL resource events and plugin tooling: inspect plugin manifest metadata."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from ..plugin import Commandlet
from ..specs import TriggerSpec
from ..toml_support import load_data_file
from .loading import load_module_path, load_plugins, load_trigger_specs
from .trust import (
    PluginManifestTrust,
    PluginTrustPolicy,
    enforce_plugin_manifest_signature,
)


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Pre-import metadata that controls filesystem plugin exposure."""

    commandlets: frozenset[str]
    triggers: tuple[TriggerSpec, ...] = ()
    commandlet_capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    default_commandlet: str | None = None
    library_backed: bool = False
    process_wrapped: bool = False
    service: bool = False
    native: bool = False
    roles: tuple[str, ...] = ()


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
    enforce_plugin_manifest_signature(manifest_path, trust_policy=trust_policy, manifest_trust=manifest_trust)
    manifest = parse_plugin_manifest(manifest_path)
    module = load_module_path(plugin_dir / "plugin.py")
    plugins = enforce_plugin_manifest(manifest, load_plugins(module), manifest_path)
    triggers = enforce_trigger_manifest(manifest, load_trigger_specs(module), manifest_path)
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
    commandlet_rows = data.get("commandlets")
    if not isinstance(commandlet_rows, list) or not commandlet_rows:
        raise ValueError(f"{source} must declare at least one [[commandlets]] entry")
    commandlets: set[str] = set()
    commandlet_capabilities: dict[str, tuple[str, ...]] = {}
    commandlet_secret_options: dict[str, tuple[str, ...]] = {}
    commandlet_provider_variables: dict[str, tuple[str, ...]] = {}
    commandlet_secret_provider_variables: dict[str, tuple[str, ...]] = {}
    for index, row in enumerate(commandlet_rows, start=1):
        # Each commandlet row is collected into per-commandlet maps so later
        # enforcement can compare manifest declarations with the concrete
        # CommandSpec produced by decorators or explicit plugin code.
        if not isinstance(row, dict):
            raise ValueError(f"{source} commandlets entry {index} must be a table")
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{source} commandlets entry {index} requires name")
        commandlets.add(name)
        context = f"commandlets entry {index}"
        commandlet_capabilities[name] = string_list_field(row, "capabilities", source, context)
        commandlet_secret_options[name] = string_list_field(row, "secret_options", source, context)
        commandlet_provider_variables[name] = string_list_field(row, "provider_variables", source, context)
        commandlet_secret_provider_variables[name] = string_list_field(row, "secret_provider_variables", source, context)
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
    if default_commandlet is not None and default_commandlet not in commandlets:
        raise ValueError(f"{source} plugin.default_commandlet must name a declared commandlet")
    triggers = parse_trigger_rows(data.get("triggers", []), source)
    return PluginManifest(
        commandlets=frozenset(commandlets),
        triggers=triggers,
        commandlet_capabilities=commandlet_capabilities,
        commandlet_secret_options=commandlet_secret_options,
        commandlet_provider_variables=commandlet_provider_variables,
        commandlet_secret_provider_variables=commandlet_secret_provider_variables,
        default_commandlet=default_commandlet,
        library_backed=library_backed,
        process_wrapped=process_wrapped,
        service=service,
        native=native or not (library_backed or process_wrapped),
        roles=roles,
    )


def parse_trigger_rows(value: Any, source: str) -> tuple[TriggerSpec, ...]:
    """Parse optional [[triggers]] manifest entries.

    Trigger rows are provider-owned automation rules.  They are parsed from the
    manifest so the registry can list and validate trigger behavior without
    trusting arbitrary top-level plugin code first.
    """
    if value in (None, []):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} triggers must be a list")
    triggers: list[TriggerSpec] = []
    names: set[str] = set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} triggers entry {index} must be a table")
        name = string_field(row, "name", source, f"triggers entry {index}")
        if name in names:
            raise ValueError(f"{source} duplicate trigger: {name}")
        names.add(name)
        topic = string_field(row, "topic", source, f"triggers entry {index}")
        action_command = string_field(row, "action_command", source, f"triggers entry {index}")
        action_mode = optional_string_field(row, "action_mode", source, f"triggers entry {index}", default="service")
        assert action_mode is not None
        if action_mode not in {"foreground", "background", "service"}:
            raise ValueError(f"{source} triggers entry {index} action_mode must be foreground, background, or service")
        payload_equals = row.get("payload_equals", {})
        # Keep manifest predicates simple and deterministic.  Complex matching
        # belongs in explicit commandlets; trigger metadata should remain
        # inspectable without importing plugin code.
        if not isinstance(payload_equals, dict):
            raise ValueError(f"{source} triggers entry {index} payload_equals must be a table")
        for key, item in payload_equals.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{source} triggers entry {index} payload_equals keys must be strings")
            if not isinstance(item, str):
                raise ValueError(f"{source} triggers entry {index} payload_equals values must be strings")
        suppress_self_trigger = row.get("suppress_self_trigger", True)
        if not isinstance(suppress_self_trigger, bool):
            raise ValueError(f"{source} triggers entry {index} suppress_self_trigger must be true or false")
        description = optional_string_field(row, "description", source, f"triggers entry {index}", default="")
        capability = optional_string_field(row, "capability", source, f"triggers entry {index}")
        triggers.append(
            TriggerSpec(
                name=name,
                topic=topic,
                action_command=action_command,
                description=description or "",
                action_mode=action_mode,
                capability=capability,
                payload_equals=tuple(sorted(payload_equals.items())),
                active_job=bool_field(row, "active_job", source, f"triggers entry {index}"),
                exclude_commandlets=string_list_field(row, "exclude_commandlets", source, f"triggers entry {index}"),
                suppress_self_trigger=suppress_self_trigger,
            )
        )
    return tuple(triggers)


def string_field(data: dict[str, Any], key: str, source: str, context: str) -> str:
    """Return a required string field."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source} {context} requires {key}")
    return value


def optional_string_field(
    data: dict[str, Any],
    key: str,
    source: str,
    context: str,
    *,
    default: str | None = None,
) -> str | None:
    """Return an optional string manifest field."""
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{source} {context}.{key} must be a string")
    return value


def enforce_plugin_manifest(
    manifest: PluginManifest,
    plugins: tuple[Commandlet, ...],
    path: Path,
) -> tuple[Commandlet, ...]:
    """Return only manifest-declared commandlets and reject missing declarations.

    This is the post-import half of the manifest contract.  The manifest says
    what may be exposed; the loaded CommandSpec says what the code actually
    exposes.  Any drift is rejected so docs, completion, trust prompts, and
    runtime enforcement are reading the same contract.
    """
    by_name = {plugin.spec.name: plugin for plugin in plugins}
    missing = sorted(manifest.commandlets.difference(by_name))
    if missing:
        raise ValueError(f"{path} declares missing commandlets: {', '.join(missing)}")
    for name in sorted(manifest.commandlets):
        # Capabilities, secret options, and provider-variable declarations must
        # match exactly.  Missing entries would weaken enforcement; stale entries
        # would make the manifest claim permissions or secrets the code does not
        # actually use.
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
        manifest_provider_vars = set(manifest.commandlet_provider_variables.get(name, ()))
        code_provider_vars = set(by_name[name].spec.provider_variables)
        if manifest_provider_vars != code_provider_vars:
            missing_provider_vars = sorted(code_provider_vars.difference(manifest_provider_vars))
            stale_provider_vars = sorted(manifest_provider_vars.difference(code_provider_vars))
            details = []
            if missing_provider_vars:
                details.append(f"missing {', '.join(missing_provider_vars)}")
            if stale_provider_vars:
                details.append(f"stale {', '.join(stale_provider_vars)}")
            raise ValueError(f"{path} provider_variables mismatch for {name}: {'; '.join(details)}")
        manifest_secret_provider_vars = set(manifest.commandlet_secret_provider_variables.get(name, ()))
        code_secret_provider_vars = set(by_name[name].spec.secret_provider_variables)
        if manifest_secret_provider_vars != code_secret_provider_vars:
            missing_secret_provider_vars = sorted(code_secret_provider_vars.difference(manifest_secret_provider_vars))
            stale_secret_provider_vars = sorted(manifest_secret_provider_vars.difference(code_secret_provider_vars))
            details = []
            if missing_secret_provider_vars:
                details.append(f"missing {', '.join(missing_secret_provider_vars)}")
            if stale_secret_provider_vars:
                details.append(f"stale {', '.join(stale_secret_provider_vars)}")
            raise ValueError(f"{path} secret_provider_variables mismatch for {name}: {'; '.join(details)}")
    return tuple(by_name[name] for name in sorted(manifest.commandlets))


def enforce_trigger_manifest(
    manifest: PluginManifest,
    triggers: tuple[TriggerSpec, ...],
    path: Path,
) -> tuple[TriggerSpec, ...]:
    """Return manifest-declared trigger specs and reject drift from code."""
    declared = {trigger.name: trigger for trigger in manifest.triggers}
    exposed: dict[str, TriggerSpec] = {}
    for trigger in triggers:
        if trigger.name in exposed:
            raise ValueError(f"{path} duplicate trigger from code: {trigger.name}")
        exposed[trigger.name] = trigger
    missing = sorted(declared.keys() - exposed.keys())
    if missing:
        raise ValueError(f"{path} declares missing triggers: {', '.join(missing)}")
    undeclared = sorted(exposed.keys() - declared.keys())
    if undeclared:
        raise ValueError(f"{path} exposes undeclared triggers: {', '.join(undeclared)}")
    for name in sorted(declared):
        if declared[name] != exposed[name]:
            raise ValueError(f"{path} trigger mismatch for {name}")
    return tuple(declared[name] for name in sorted(declared))



def table_value(data: dict[str, Any], key: str, source: str) -> dict[str, Any]:
    """Return one TOML table from a manifest."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{source} [{key}] must be a table")
    return value


def bool_field(data: dict[str, Any], key: str, source: str, context: str = "plugin") -> bool:
    """Return a boolean manifest field."""
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{source} {context}.{key} must be true or false")
    return value


def list_field(data: dict[str, Any], key: str, source: str) -> list[Any]:
    """Return a list manifest field."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} plugin.{key} must be a list")
    return value


def string_list_field(data: dict[str, Any], key: str, source: str, context: str) -> tuple[str, ...]:
    """Return an optional list field that must contain only non-empty strings."""
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.{key} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source} {context}.{key} entry {index} must be a string")
    return tuple(value)

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
