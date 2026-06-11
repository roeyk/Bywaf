"""Plugin manifest data model.

Provides `PluginManifest`, the parsed pre-import metadata for one provider.

Used by:
- `registry.manifest`: builds the model from TOML data.
- manifest graph/dependency/enforcement modules: inspect provider contracts
  without importing plugin code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...event.schemas import EventSchema
from ...specs import ArgumentSpec, OptionSpec, TriggerSpec


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Pre-import metadata that controls filesystem plugin exposure.

    Constructed by: `parse_plugin_manifest_data()`.
    Consumed by: registry loading, manifest dependency graph construction, and
    post-import drift enforcement.
    """

    commandlets: frozenset[str]
    version: str
    requires_bywaf: str | None = None
    requires_schemas: tuple[str, ...] = ()
    requires_plugins: tuple[str, ...] = ()
    triggers: tuple[TriggerSpec, ...] = ()
    commandlet_capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_database_actions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_consumes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_emits: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_options: dict[str, tuple[OptionSpec, ...]] = field(default_factory=dict)
    commandlet_arguments: dict[str, tuple[ArgumentSpec, ...]] = field(default_factory=dict)
    commandlet_secret_options: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_provider_variables: dict[str, tuple[str, ...]] = field(default_factory=dict)
    commandlet_secret_vars: dict[str, tuple[str, ...]] = field(default_factory=dict)
    event_schemas: tuple[EventSchema, ...] = ()
    default_commandlet: str | None = None
    library_backed: bool = False
    process_wrapped: bool = False
    service: bool = False
    native: bool = False
    roles: tuple[str, ...] = ()
