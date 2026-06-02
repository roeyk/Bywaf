"""Plugin manifest parsing and code/manifest drift checks.

Provides `PluginManifest`, TOML parsing helpers, trigger metadata parsing,
filesystem package loading, and commandlet/trigger manifest enforcement.

Used by:
- registry.core: validates bundled and filesystem providers.
- REPL resource events and plugin tooling: inspect plugin manifest metadata."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any

from ..event.schemas import EventSchema, register_event_schemas
from ..plugin import Commandlet
from ..specs import ArgumentSpec, OptionSpec, TriggerSpec
from ..toml_support import load_data_file
from .loading import load_module_path, load_plugins, load_trigger_specs
from .manifest_fields import (
    argument_rows_field,
    bool_field,
    database_actions_field,
    list_field as list_field,
    option_rows_field,
    optional_string_field,
    string_field as string_field,
    string_list_field,
    table_value,
    validate_requires_bywaf,
    validate_version_string,
)
from .manifest_schemas import parse_event_schema_rows
from .manifest_triggers import parse_trigger_rows
from .trust import (
    PluginManifestTrust,
    PluginTrustPolicy,
    enforce_plugin_manifest_signature,
)


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Pre-import metadata that controls filesystem plugin exposure."""

    commandlets: frozenset[str]
    version: str
    requires_bywaf: str | None = None
    triggers: tuple[TriggerSpec, ...] = ()
    commandlet_capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_database_actions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_consumes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_emits: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_options: dict[str, tuple[OptionSpec, ...]] = field(default_factory=dict)
    commandlet_arguments: dict[str, tuple[ArgumentSpec, ...]] = field(default_factory=dict)
    commandlet_secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    event_schemas: tuple[EventSchema, ...] = ()
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
    version = optional_string_field(plugin_data, "version", source, "plugin", default="0.0.0") or "0.0.0"
    validate_version_string(version, source, "plugin.version")
    requires_bywaf = optional_string_field(plugin_data, "requires_bywaf", source, "plugin")
    if requires_bywaf is not None:
        validate_requires_bywaf(requires_bywaf, source, "plugin.requires_bywaf")
    commandlet_rows = data.get("commandlets")
    if not isinstance(commandlet_rows, list) or not commandlet_rows:
        raise ValueError(f"{source} must declare at least one [[commandlets]] entry")
    commandlets: set[str] = set()
    commandlet_capabilities: dict[str, tuple[str, ...]] = {}
    commandlet_database_actions: dict[str, tuple[str, ...]] = {}
    commandlet_consumes: dict[str, tuple[str, ...]] = {}
    commandlet_emits: dict[str, tuple[str, ...]] = {}
    commandlet_options: dict[str, tuple[OptionSpec, ...]] = {}
    commandlet_arguments: dict[str, tuple[ArgumentSpec, ...]] = {}
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
        commandlet_database_actions[name] = database_actions_field(row, source, context)
        commandlet_consumes[name] = string_list_field(row, "consumes", source, context)
        commandlet_emits[name] = string_list_field(row, "emits", source, context)
        commandlet_options[name] = option_rows_field(row, source, context)
        commandlet_arguments[name] = argument_rows_field(row, source, context)
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
    event_schemas = parse_event_schema_rows(data.get("event_schemas", []), source)
    return PluginManifest(
        commandlets=frozenset(commandlets),
        version=version,
        requires_bywaf=requires_bywaf,
        triggers=triggers,
        commandlet_capabilities=commandlet_capabilities,
        commandlet_database_actions=commandlet_database_actions,
        commandlet_consumes=commandlet_consumes,
        commandlet_emits=commandlet_emits,
        commandlet_options=commandlet_options,
        commandlet_arguments=commandlet_arguments,
        commandlet_secret_options=commandlet_secret_options,
        commandlet_provider_variables=commandlet_provider_variables,
        commandlet_secret_provider_variables=commandlet_secret_provider_variables,
        event_schemas=event_schemas,
        default_commandlet=default_commandlet,
        library_backed=library_backed,
        process_wrapped=process_wrapped,
        service=service,
        native=native or not (library_backed or process_wrapped),
        roles=roles,
    )


def enforce_plugin_manifest(
    manifest: PluginManifest,
    plugins: tuple[Commandlet, ...],
    path: Path,
    *,
    hydrate_specs: bool = False,
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
        if hydrate_specs:
            hydrate_command_spec_from_manifest(by_name[name], manifest, name)
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
        manifest_database_actions = set(manifest.commandlet_database_actions.get(name, ()))
        code_database_actions = set(by_name[name].spec.database_actions)
        if manifest_database_actions != code_database_actions:
            missing_actions = sorted(code_database_actions.difference(manifest_database_actions))
            stale_actions = sorted(manifest_database_actions.difference(code_database_actions))
            details = []
            if missing_actions:
                details.append(f"missing {', '.join(missing_actions)}")
            if stale_actions:
                details.append(f"stale {', '.join(stale_actions)}")
            raise ValueError(f"{path} database_actions mismatch for {name}: {'; '.join(details)}")
        manifest_consumes = set(manifest.commandlet_consumes.get(name, ()))
        code_consumes = set(by_name[name].spec.consumes)
        if manifest_consumes and manifest_consumes != code_consumes:
            raise ValueError(f"{path} consumes mismatch for {name}")
        manifest_emits = set(manifest.commandlet_emits.get(name, ()))
        code_emits = set(by_name[name].spec.emits)
        if manifest_emits and manifest_emits != code_emits:
            raise ValueError(f"{path} emits mismatch for {name}")
        manifest_options = manifest.commandlet_options.get(name, ())
        if manifest_options and manifest_options != by_name[name].spec.options:
            raise ValueError(f"{path} options mismatch for {name}")
        manifest_arguments = manifest.commandlet_arguments.get(name, ())
        if manifest_arguments and manifest_arguments != by_name[name].spec.arguments:
            raise ValueError(f"{path} arguments mismatch for {name}")
        declared_secret_options = {
            option.name
            for option in manifest.commandlet_options.get(name, ())
            if option.secret
        }
        manifest_secret_options = set(manifest.commandlet_secret_options.get(name, ())).union(declared_secret_options)
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


def hydrate_command_spec_from_manifest(plugin: Commandlet, manifest: PluginManifest, name: str) -> None:
    """Overlay sidecar-owned bundled metadata onto a runtime command spec."""
    spec = plugin.spec
    plugin.spec = replace(
        spec,
        capabilities=manifest.commandlet_capabilities.get(name, spec.capabilities),
        database_actions=manifest.commandlet_database_actions.get(name, spec.database_actions),
        consumes=manifest.commandlet_consumes.get(name, spec.consumes) or spec.consumes,
        emits=manifest.commandlet_emits.get(name, spec.emits) or spec.emits,
        options=manifest.commandlet_options.get(name, spec.options) or spec.options,
        arguments=manifest.commandlet_arguments.get(name, spec.arguments) or spec.arguments,
        provider_variables=manifest.commandlet_provider_variables.get(name, spec.provider_variables),
        secret_provider_variables=manifest.commandlet_secret_provider_variables.get(
            name,
            spec.secret_provider_variables,
        ),
    )


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
