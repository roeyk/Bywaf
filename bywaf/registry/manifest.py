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

from ..event.schemas import EVENT_SCHEMAS, FIELD_TYPES, EventSchema, FieldSchema, register_event_schemas
from ..plugin import Commandlet
from ..specs import ArgumentSpec, CompletionSpec, OptionSpec, TriggerSpec
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


def parse_event_schema_rows(value: Any, source: str) -> tuple[EventSchema, ...]:
    """Parse optional plugin-owned event schema manifest entries."""
    if value in (None, []):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} event_schemas must be a list")
    schemas: list[EventSchema] = []
    topics: set[str] = set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} event_schemas entry {index} must be a table")
        context = f"event_schemas entry {index}"
        topic = string_field(row, "topic", source, context)
        if topic in EVENT_SCHEMAS:
            raise ValueError(f"{source} {context}.topic is framework-owned: {topic}")
        if topic in topics:
            raise ValueError(f"{source} duplicate event schema: {topic}")
        topics.add(topic)
        summary = optional_string_field(row, "summary", source, context, default="") or ""
        fields = event_schema_fields(row.get("fields", []), source, context)
        if not fields:
            raise ValueError(f"{source} {context}.fields must declare at least one field")
        schemas.append(
            EventSchema(
                topic=topic,
                summary=summary,
                fields=fields,
                notes=string_list_field(row, "notes", source, context),
                version=optional_string_field(row, "version", source, context, default="1") or "1",
            )
        )
    return tuple(schemas)


def event_schema_fields(value: Any, source: str, context: str) -> tuple[FieldSchema, ...]:
    """Parse one event schema's field rows."""
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.fields must be a list")
    fields: list[FieldSchema] = []
    names: set[str] = set()
    for index, row in enumerate(value, start=1):
        field_context = f"{context}.fields entry {index}"
        if not isinstance(row, dict):
            raise ValueError(f"{source} {field_context} must be a table")
        name = string_field(row, "name", source, field_context)
        if name in names:
            raise ValueError(f"{source} {context}.fields duplicate field: {name}")
        names.add(name)
        field_type = optional_string_field(row, "type", source, field_context, default="any") or "any"
        if field_type not in FIELD_TYPES:
            raise ValueError(f"{source} {field_context}.type must be one of: {', '.join(FIELD_TYPES)}")
        fields.append(
            FieldSchema(
                name=name,
                field_type=field_type,
                required=bool_field(row, "required", source, field_context),
                description=optional_string_field(row, "description", source, field_context, default="") or "",
                allowed=string_list_field(row, "allowed", source, field_context),
            )
        )
    return tuple(fields)


def option_rows_field(data: dict[str, Any], source: str, context: str) -> tuple[OptionSpec, ...]:
    """Parse optional commandlet option metadata rows."""
    value = data.get("options", ())
    if value in (None, ()):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.options must be a list")
    return tuple(option_row_field(row, source, f"{context}.options entry {index}") for index, row in enumerate(value, start=1))


def option_row_field(row: Any, source: str, context: str) -> OptionSpec:
    """Parse one manifest commandlet option row."""
    if not isinstance(row, dict):
        raise ValueError(f"{source} {context} must be a table")
    value_type = optional_string_field(row, "type", source, context, default="str") or "str"
    if value_type not in {"str", "int", "optional-int", "float", "bool"}:
        raise ValueError(f"{source} {context}.type must be one of: str, int, optional-int, float, bool")
    completion = optional_string_field(row, "completion", source, context)
    return OptionSpec(
        name=string_field(row, "name", source, context),
        description=optional_string_field(row, "description", source, context, default="") or "",
        default=manifest_default_to_string(row.get("default")),
        choices=string_list_field(row, "choices", source, context),
        completion=CompletionSpec(completion or "none"),
        secret=bool_field(row, "secret", source, context),
        value_type=value_type,
    )


def argument_rows_field(data: dict[str, Any], source: str, context: str) -> tuple[ArgumentSpec, ...]:
    """Parse optional commandlet argument metadata rows."""
    value = data.get("arguments", ())
    if value in (None, ()):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} {context}.arguments must be a list")
    return tuple(argument_row_field(row, source, f"{context}.arguments entry {index}") for index, row in enumerate(value, start=1))


def argument_row_field(row: Any, source: str, context: str) -> ArgumentSpec:
    """Parse one manifest commandlet argument row."""
    if not isinstance(row, dict):
        raise ValueError(f"{source} {context} must be a table")
    nargs = optional_string_field(row, "nargs", source, context, default="") or ""
    completion = optional_string_field(row, "completion", source, context)
    return ArgumentSpec(
        name=string_field(row, "name", source, context),
        description=optional_string_field(row, "description", source, context, default="") or "",
        required=nargs not in {"?", "*"},
        completion=CompletionSpec(completion or "none"),
    )


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


def manifest_default_to_string(value: Any) -> str | None:
    """Normalize manifest defaults into CommandSpec string metadata."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


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


def database_actions_field(data: dict[str, Any], source: str, context: str) -> tuple[str, ...]:
    """Return commandlet database action metadata from list/string/booleans."""
    direct = data.get("database_actions")
    if direct is not None:
        if isinstance(direct, str):
            items = [item.strip() for item in direct.split(",") if item.strip()]
        elif isinstance(direct, list):
            items = direct
        else:
            raise ValueError(f"{source} {context}.database_actions must be a string or list")
        return normalize_database_actions(items, source, f"{context}.database_actions")
    database = data.get("database", {})
    if database in ({}, None):
        return ()
    if not isinstance(database, dict):
        raise ValueError(f"{source} {context}.database must be a table")
    actions = database.get("actions", {})
    if not isinstance(actions, dict):
        raise ValueError(f"{source} {context}.database.actions must be a table")
    selected: list[str] = []
    for action in ("view", "write", "manage"):
        enabled = actions.get(action, False)
        if not isinstance(enabled, bool):
            raise ValueError(f"{source} {context}.database.actions.{action} must be true or false")
        if enabled:
            selected.append(action)
    return tuple(selected)


def normalize_database_actions(items: list[Any], source: str, context: str) -> tuple[str, ...]:
    """Validate and order database action names."""
    allowed = ("view", "write", "manage")
    selected: set[str] = set()
    for index, item in enumerate(items, start=1):
        if not isinstance(item, str):
            raise ValueError(f"{source} {context} entry {index} must be a string")
        if item not in allowed:
            raise ValueError(f"{source} {context} entry {index} must be one of: {', '.join(allowed)}")
        selected.add(item)
    return tuple(action for action in allowed if action in selected)


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
