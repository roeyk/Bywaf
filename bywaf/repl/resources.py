"""Public facade for REPL project and load/save resource helpers.

Provides the stable resource API used by command handlers and CLI startup while
delegating parsing, persistence, scripts, projects, and audit metadata to
cohesive sibling modules.

Used by:
- REPL command handlers: implement `load`, `save`, and `project` built-ins.
- CLI startup: import resource defaults, config loading, secret hydration, and
  script execution helpers.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..runner import Runner
from .persistence import apply_config
from .persistence import load_config
from .persistence import load_database
from .persistence import load_history
from .persistence import prompt_database_passphrase
from .persistence import save_config
from .persistence import save_database
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


def load_repl_resource(runner: Runner, spec: str, state: ResourceState | None = None) -> None:
    """Handle `load key=value` resources from the REPL."""
    state = state or default_resource_state(runner)
    forced, resource = parse_load_spec(spec)
    key, value = parse_resource_assignment(resource)
    handler = LOAD_RESOURCE_HANDLERS.get(key)
    if handler is None or (not value and key not in DEFAULT_LOAD_RESOURCE_KEYS):
        print("usage: load [--force] plugin=<path>, load script=<path>, load db=<path>, load config=<path>, or load history=<path>")
        return
    handler(runner, state, value, forced)


LoadResourceHandler = Callable[[Runner, ResourceState, str, bool], None]


def load_db_resource(runner: Runner, state: ResourceState, value: str, forced: bool) -> None:
    """Load a database resource."""
    del state, forced
    load_database(runner, resolve_resource_path(value, Path("."), DEFAULT_DATABASE))


def load_config_resource(runner: Runner, state: ResourceState, value: str, forced: bool) -> None:
    """Load a config resource."""
    del state, forced
    load_config(runner, resolve_resource_path(value, Path("."), DEFAULT_CONFIG))


def load_history_resource(runner: Runner, state: ResourceState, value: str, forced: bool) -> None:
    """Load a history resource."""
    del runner, forced
    load_history(state, resolve_resource_path(value, Path("."), DEFAULT_HISTORY))


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


def load_script_resource(runner: Runner, state: ResourceState, value: str, forced: bool) -> None:
    """Load and execute a script resource."""
    del forced
    run_script(runner, resolve_resource_path(value, Path(".")), state)


LOAD_RESOURCE_HANDLERS: dict[str, LoadResourceHandler] = {
    "config": load_config_resource,
    "db": load_db_resource,
    "history": load_history_resource,
    "plugin": load_plugin_resource,
    "script": load_script_resource,
}


def save_repl_resource(runner: Runner, spec: str, state: ResourceState | None = None) -> None:
    """Handle `save key=value` resources from the REPL."""
    state = state or default_resource_state(runner)
    encrypt, resource = parse_save_spec(spec)
    key, value = parse_resource_assignment(resource)
    handler = SAVE_RESOURCE_HANDLERS.get(key)
    if handler is None or (not value and key not in DEFAULT_SAVE_RESOURCE_KEYS):
        print("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
        return
    handler(runner, state, value, encrypt)


SaveResourceHandler = Callable[[Runner, ResourceState, str, bool], None]


def save_db_resource(runner: Runner, state: ResourceState, value: str, encrypt: bool) -> None:
    """Save a database resource."""
    del state
    save_database(runner, resolve_resource_path(value, Path("."), DEFAULT_DATABASE), encrypt=encrypt)


def save_config_resource(runner: Runner, state: ResourceState, value: str, encrypt: bool) -> None:
    """Save a config resource."""
    del state, encrypt
    save_config(runner, resolve_resource_path(value, Path("."), DEFAULT_CONFIG))


def save_history_resource(runner: Runner, state: ResourceState, value: str, encrypt: bool) -> None:
    """Save a history resource."""
    del runner, encrypt
    save_history(state, resolve_resource_path(value, Path("."), DEFAULT_HISTORY))


SAVE_RESOURCE_HANDLERS: dict[str, SaveResourceHandler] = {
    "config": save_config_resource,
    "db": save_db_resource,
    "history": save_history_resource,
}
