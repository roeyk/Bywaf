"""Commandlet-row parsing for plugin manifests.

Used by: `registry.manifest.parse_plugin_manifest_data()` while converting raw
`[[commandlets]]` TOML rows into the parallel maps stored on `PluginManifest`.
Keeping this logic separate makes top-level manifest parsing easier to scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...specs import ArgumentSpec, OptionSpec
from .fields import (
    argument_rows_field,
    database_actions_field,
    option_rows_field,
    require_known_keys,
    string_list_field,
)


@dataclass(frozen=True, slots=True)
class ManifestCommandletRows:
    """Normalized commandlet declarations from raw TOML rows.

    Constructed by: `parse_manifest_commandlets()`.

    Consumed by: `parse_plugin_manifest_data()` when it assembles the final
    `PluginManifest` value. The parallel maps are keyed by commandlet name so
    manifest/code enforcement can compare each contract surface independently.
    """

    names: frozenset[str]
    capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    database_actions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    consumes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    emits: dict[str, tuple[str, ...]] = field(default_factory=dict)
    options: dict[str, tuple[OptionSpec, ...]] = field(default_factory=dict)
    arguments: dict[str, tuple[ArgumentSpec, ...]] = field(default_factory=dict)
    secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    secret_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)


COMMANDLET_ROW_KEYS = {
    "name",
    "module",
    "description",
    "usage",
    "examples",
    "capabilities",
    "consumes",
    "emits",
    "database",
    "database_actions",
    "options",
    "arguments",
    "secret_options",
    "provider_variables",
    "secret_provider_variables",
}


def parse_manifest_commandlets(commandlet_rows: Any, source: str) -> ManifestCommandletRows:
    """Parse all `[[commandlets]]` rows into name-keyed contract maps."""
    if not isinstance(commandlet_rows, list) or not commandlet_rows:
        raise ValueError(f"{source} must declare at least one [[commandlets]] entry")
    commandlets: set[str] = set()
    capabilities: dict[str, tuple[str, ...]] = {}
    database_actions: dict[str, tuple[str, ...]] = {}
    consumes: dict[str, tuple[str, ...]] = {}
    emits: dict[str, tuple[str, ...]] = {}
    options: dict[str, tuple[OptionSpec, ...]] = {}
    arguments: dict[str, tuple[ArgumentSpec, ...]] = {}
    secret_options: dict[str, tuple[str, ...]] = {}
    provider_variables: dict[str, tuple[str, ...]] = {}
    secret_provider_variables: dict[str, tuple[str, ...]] = {}

    for index, row in enumerate(commandlet_rows, start=1):
        parsed = parse_manifest_commandlet_row(row, source, index)
        name = parsed.name
        commandlets.add(name)
        capabilities[name] = parsed.capabilities
        database_actions[name] = parsed.database_actions
        consumes[name] = parsed.consumes
        emits[name] = parsed.emits
        options[name] = parsed.options
        arguments[name] = parsed.arguments
        secret_options[name] = parsed.secret_options
        provider_variables[name] = parsed.provider_variables
        secret_provider_variables[name] = parsed.secret_provider_variables

    return ManifestCommandletRows(
        names=frozenset(commandlets),
        capabilities=capabilities,
        database_actions=database_actions,
        consumes=consumes,
        emits=emits,
        options=options,
        arguments=arguments,
        secret_options=secret_options,
        provider_variables=provider_variables,
        secret_provider_variables=secret_provider_variables,
    )


@dataclass(frozen=True, slots=True)
class ManifestCommandletRow:
    """One normalized manifest commandlet row.

    Constructed by: `parse_manifest_commandlet_row()`.

    Consumed by: `parse_manifest_commandlets()` to populate the final
    name-keyed commandlet contract maps.
    """

    name: str
    capabilities: tuple[str, ...]
    database_actions: tuple[str, ...]
    consumes: tuple[str, ...]
    emits: tuple[str, ...]
    options: tuple[OptionSpec, ...]
    arguments: tuple[ArgumentSpec, ...]
    secret_options: tuple[str, ...]
    provider_variables: tuple[str, ...]
    secret_provider_variables: tuple[str, ...]


def parse_manifest_commandlet_row(row: Any, source: str, index: int) -> ManifestCommandletRow:
    """Parse one `[[commandlets]]` row from a plugin manifest."""
    if not isinstance(row, dict):
        raise ValueError(f"{source} commandlets entry {index} must be a table")
    require_known_keys(row, COMMANDLET_ROW_KEYS, source, f"commandlets entry {index}")
    name = row.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"{source} commandlets entry {index} requires name")
    context = f"commandlets entry {index}"
    return ManifestCommandletRow(
        name=name,
        capabilities=string_list_field(row, "capabilities", source, context),
        database_actions=database_actions_field(row, source, context),
        consumes=string_list_field(row, "consumes", source, context),
        emits=string_list_field(row, "emits", source, context),
        options=option_rows_field(row, source, context),
        arguments=argument_rows_field(row, source, context),
        secret_options=string_list_field(row, "secret_options", source, context),
        provider_variables=string_list_field(row, "provider_variables", source, context),
        secret_provider_variables=string_list_field(row, "secret_provider_variables", source, context),
    )
