"""Public facade for REPL project and resource helpers.

Provides the stable resource API used by command handlers and CLI startup while
delegating parsing, persistence, scripts, projects, and audit metadata to
cohesive sibling modules.

Used by:
- REPL command handlers: implement plugin loading, scripts, and projects.
- CLI startup: import resource defaults, config loading, secret hydration, and
  script execution helpers.
"""

from __future__ import annotations

from collections.abc import Callable

from ..runner import Runner
from .persistence import apply_config
from .persistence import load_database
from .persistence import load_history
from .persistence import prompt_database_passphrase
from .persistence import save_history
from .projects import dispatch_project_command
from .projects import print_project_info
from .resource.events import plugin_manifest_audit_details
from .resource.events import publish_resource_loaded
from .resource.specs import DEFAULT_CONFIG
from .resource.specs import DEFAULT_CONFIG_DIR
from .resource.specs import DEFAULT_DATABASE
from .resource.specs import DEFAULT_DATABASE_DIR
from .resource.specs import DEFAULT_HISTORY
from .resource.specs import DEFAULT_LOAD_RESOURCE_KEYS
from .resource.specs import DEFAULT_PLUGIN_DIR
from .resource.specs import DEFAULT_SAVE_RESOURCE_KEYS
from .resource.specs import DEFAULT_SCRIPT_DIR
from .resource.specs import DEFAULT_SETTINGS
from .resource.specs import parse_load_spec
from .resource.specs import parse_resource_assignment
from .resource.specs import parse_save_spec
from .resource.specs import resolve_resource_path
from .scripts import run_script
from .scripts import script_commands
from .scripts import strip_inline_comment
from .state import ResourceState
from .state import default_resource_state
from .state import hydrate_persistent_secrets

# This facade keeps older imports stable after the resource layer was split
# across persistence, scripts, projects, specs, state, and audit-event modules.
__all__ = [
    "DEFAULT_CONFIG",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_DATABASE",
    "DEFAULT_DATABASE_DIR",
    "DEFAULT_HISTORY",
    "DEFAULT_LOAD_RESOURCE_KEYS",
    "DEFAULT_PLUGIN_DIR",
    "DEFAULT_SAVE_RESOURCE_KEYS",
    "DEFAULT_SCRIPT_DIR",
    "DEFAULT_SETTINGS",
    "ResourceState",
    "apply_config",
    "default_resource_state",
    "dispatch_project_command",
    "hydrate_persistent_secrets",
    "load_database",
    "load_history",
    "load_repl_resource",
    "load_plugin_resource",
    "parse_load_spec",
    "parse_resource_assignment",
    "parse_save_spec",
    "plugin_manifest_audit_details",
    "print_project_info",
    "prompt_database_passphrase",
    "publish_resource_loaded",
    "resolve_resource_path",
    "run_script",
    "save_history",
    "script_commands",
    "strip_inline_comment",
]


def load_repl_resource(runner: Runner, spec: str, state: ResourceState | None = None) -> None:
    """Handle `plugin load=<path>` resources from the REPL.

    Called by: REPL resource/plugin command handlers after parsing user input.
    """
    state = state or default_resource_state(runner)
    forced, resource, catalog_path = parse_load_spec(spec)
    key, value = parse_resource_assignment(resource)
    # This lookup uses LOAD_RESOURCE_HANDLERS, defined below, in place of an
    # if/elif ladder over loadable resource kinds.
    handler = LOAD_RESOURCE_HANDLERS.get(key)
    if handler is None or not value:
        print("usage: plugin load=<path> [--force]")
        return
    if key == "plugin":
        # Plugin loading has extra catalog-path and manifest audit details, so
        # keep it on a dedicated path rather than the generic handler signature.
        load_plugin_resource(runner, state, value, forced, catalog_path=catalog_path)
        return
    handler(runner, state, value, forced)


LoadResourceHandler = Callable[[Runner, ResourceState, str, bool], list[str]]


def load_plugin_resource(
    runner: Runner,
    state: ResourceState,
    value: str,
    forced: bool,
    *,
    catalog_path: str | None = None,
) -> list[str]:
    """Load a filesystem plugin resource.

    Called by: `load_repl_resource()` and plugin-loading command handlers.
    """
    del state
    plugin_path = resolve_resource_path(value, DEFAULT_PLUGIN_DIR)
    # The filesystem path is where the plugin lives on disk. catalog_path, when
    # supplied, is the logical provider path exposed to users and variables.
    runner.registry.load_filesystem_entry(plugin_path.parent, plugin_path.name, catalog_path=catalog_path, forced=forced)
    provider = catalog_path or plugin_path.name
    commandlets = runner.registry.provider_commandlet_names(provider)
    manifest_details = plugin_manifest_audit_details(plugin_path)
    # Loading a plugin is a resource mutation, so publish an audit event that
    # records both the filesystem source and logical provider/commandlet names.
    event = publish_resource_loaded(
        runner,
        "plugin",
        path=plugin_path,
        details={
            "provider": provider,
            "commandlet": commandlets[0] if commandlets else "",
            "commandlets": commandlets,
            **manifest_details,
        },
    )
    print(f"loaded {', '.join(commandlets)} serial={event.payload['serial']}")
    return commandlets


# `load <kind>=...` is a small resource-dispatch surface. load_resource() uses
# this dispatch table so each loadable resource kind can validate and publish
# its own audit event without growing a branch ladder.
LOAD_RESOURCE_HANDLERS: dict[str, LoadResourceHandler] = {
    "plugin": load_plugin_resource,
}
