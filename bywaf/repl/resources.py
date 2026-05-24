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
from .resource_events import plugin_manifest_audit_details
from .resource_events import publish_resource_loaded
from .resource_specs import DEFAULT_CONFIG
from .resource_specs import DEFAULT_CONFIG_DIR
from .resource_specs import DEFAULT_DATABASE
from .resource_specs import DEFAULT_DATABASE_DIR
from .resource_specs import DEFAULT_HISTORY
from .resource_specs import DEFAULT_LOAD_RESOURCE_KEYS
from .resource_specs import DEFAULT_PLUGIN_DIR
from .resource_specs import DEFAULT_SAVE_RESOURCE_KEYS
from .resource_specs import DEFAULT_SCRIPT_DIR
from .resource_specs import DEFAULT_SETTINGS
from .resource_specs import parse_load_spec
from .resource_specs import parse_resource_assignment
from .resource_specs import parse_save_spec
from .resource_specs import resolve_resource_path
from .scripts import run_script
from .scripts import script_commands
from .scripts import strip_inline_comment
from .state import ResourceState
from .state import default_resource_state
from .state import hydrate_persistent_secrets

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
    """Handle `load plugin=<path>` resources from the REPL."""
    state = state or default_resource_state(runner)
    forced, resource = parse_load_spec(spec)
    key, value = parse_resource_assignment(resource)
    handler = LOAD_RESOURCE_HANDLERS.get(key)
    if handler is None or not value:
        print("usage: load [--force] plugin=<path>")
        return
    handler(runner, state, value, forced)


LoadResourceHandler = Callable[[Runner, ResourceState, str, bool], None]


def load_plugin_resource(runner: Runner, state: ResourceState, value: str, forced: bool) -> None:
    """Load a filesystem plugin resource."""
    del state
    plugin_path = resolve_resource_path(value, DEFAULT_PLUGIN_DIR)
    runner.registry.load_filesystem_entry(plugin_path.parent, plugin_path.name, forced=forced)
    commandlets = runner.registry.providers.get(plugin_path.name, [])
    manifest_details = plugin_manifest_audit_details(plugin_path)
    event = publish_resource_loaded(
        runner,
        "plugin",
        path=plugin_path,
        details={
            "provider": plugin_path.name,
            "commandlet": commandlets[0] if commandlets else "",
            "commandlets": commandlets,
            **manifest_details,
        },
    )
    print(f"loaded {', '.join(commandlets)} serial={event.payload['serial']}")


LOAD_RESOURCE_HANDLERS: dict[str, LoadResourceHandler] = {
    "plugin": load_plugin_resource,
}
