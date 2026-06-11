"""Post-import plugin manifest enforcement.

Provides commandlet and trigger drift checks after plugin code has been loaded.

Used by:
- `registry.manifest.load_filesystem_plugin_package()`: validates filesystem
  plugin code against pre-import TOML metadata.
- `registry.loading_registry.PluginRegistryLoadingMixin`: validates bundled
  plugin metadata after import and optionally hydrates runtime specs.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Iterable

from ...plugin import Commandlet
from ...specs import TriggerSpec
from .model import PluginManifest


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
        plugin = by_name[name]
        if hydrate_specs:
            hydrate_command_spec_from_manifest(plugin, manifest, name)
        enforce_commandlet_manifest_entry(manifest, plugin, path, name)
    return tuple(by_name[name] for name in sorted(manifest.commandlets))


def enforce_commandlet_manifest_entry(
    manifest: PluginManifest,
    plugin: Commandlet,
    path: Path,
    name: str,
) -> None:
    """Reject drift between one manifest row and its runtime command spec."""
    spec = plugin.spec
    # Capabilities, secret options, and provider variables must match exactly:
    # missing entries weaken enforcement, while stale entries overstate what
    # the code can use.
    require_exact_set(path, name, "capabilities", manifest.commandlet_capabilities.get(name, ()), spec.capabilities)
    require_exact_set(path, name, "database_actions", manifest.commandlet_database_actions.get(name, ()), spec.database_actions)
    require_optional_set(path, name, "consumes", manifest.commandlet_consumes.get(name, ()), spec.consumes)
    require_optional_set(path, name, "emits", manifest.commandlet_emits.get(name, ()), spec.emits)
    require_optional_sequence(path, name, "options", manifest.commandlet_options.get(name, ()), spec.options)
    require_optional_sequence(path, name, "arguments", manifest.commandlet_arguments.get(name, ()), spec.arguments)
    require_exact_set(path, name, "secret_options", manifest_secret_options(manifest, name), (option.name for option in spec.options if option.secret))
    require_exact_set(path, name, "provider_variables", manifest.commandlet_provider_variables.get(name, ()), spec.provider_variables)
    require_exact_set(
        path,
        name,
        "secret_provider_variables",
        manifest.commandlet_secret_provider_variables.get(name, ()),
        spec.secret_provider_variables,
    )


def manifest_secret_options(manifest: PluginManifest, name: str) -> set[str]:
    """Return explicit and option-row-derived secret option names."""
    return set(manifest.commandlet_secret_options.get(name, ())).union(
        option.name
        for option in manifest.commandlet_options.get(name, ())
        if option.secret
    )


def require_exact_set(
    path: Path,
    name: str,
    label: str,
    manifest_values: Iterable[str],
    code_values: Iterable[str],
) -> None:
    """Require exact set parity for security-sensitive manifest fields."""
    manifest_set = set(manifest_values)
    code_set = set(code_values)
    if manifest_set == code_set:
        return
    raise ValueError(f"{path} {label} mismatch for {name}: {set_mismatch_details(manifest_set, code_set)}")


def require_optional_set(
    path: Path,
    name: str,
    label: str,
    manifest_values: Iterable[str],
    code_values: Iterable[str],
) -> None:
    """Require parity only when an optional manifest field is declared."""
    manifest_set = set(manifest_values)
    if manifest_set and manifest_set != set(code_values):
        raise ValueError(f"{path} {label} mismatch for {name}")


def require_optional_sequence(
    path: Path,
    name: str,
    label: str,
    manifest_values: tuple[object, ...],
    code_values: tuple[object, ...],
) -> None:
    """Require exact tuple parity only when an optional manifest field exists."""
    if manifest_values and manifest_values != code_values:
        raise ValueError(f"{path} {label} mismatch for {name}")


def set_mismatch_details(manifest_values: set[str], code_values: set[str]) -> str:
    """Return a stable missing/stale summary for manifest drift errors."""
    details = []
    missing = sorted(code_values.difference(manifest_values))
    stale = sorted(manifest_values.difference(code_values))
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if stale:
        details.append(f"stale {', '.join(stale)}")
    return "; ".join(details)


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
