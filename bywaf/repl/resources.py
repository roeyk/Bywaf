"""REPL project and load/save resource helpers.

Provides load/save dispatch for databases, configs, history, plugins, scripts,
and project commands, plus parsing and default path resolution for those specs.

Used by:
- REPL command handlers: implement `load`, `save`, and `project` built-ins.
- CLI startup: apply config, hydrate secrets, and run scripts."""


from __future__ import annotations

import getpass
import hashlib
import json
import os
import signal
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, cast

from ..config import Settings
from ..db import EventStore, database_appears_encrypted, export_encrypted_database, export_plaintext_database
from ..events import Event
from ..projects import ProjectPaths, create_project, list_projects, require_project
from ..registry import PluginRegistry, parse_plugin_manifest
from ..runner import Runner, new_run_id
from ..toml_support import dump_variables_toml, load_data_file

DEFAULT_SETTINGS = Settings()
DEFAULT_DATABASE = DEFAULT_SETTINGS.database
DEFAULT_CONFIG = DEFAULT_SETTINGS.config
DEFAULT_HISTORY = DEFAULT_SETTINGS.history
DEFAULT_PLUGIN_DIR = DEFAULT_SETTINGS.plugin_dir
DEFAULT_SCRIPT_DIR = DEFAULT_SETTINGS.script_dir
DEFAULT_DATABASE_DIR = DEFAULT_SETTINGS.database_dir
DEFAULT_CONFIG_DIR = DEFAULT_SETTINGS.config_dir


class ResourceState(Protocol):
    """Mutable shell state used by resource commands."""

    history_path: Path
    session_history: list[str]
    completer: Any | None


def default_resource_state(runner: Runner) -> ResourceState:
    """Create default resource state without importing repl at module load time."""
    from .shell import new_shell_state

    return new_shell_state(runner)


def dispatch_script_command(runner: Runner, command: str, state: ResourceState) -> str | None:
    """Dispatch one script command without importing repl at module load time."""
    from .shell import dispatch_repl_line

    return dispatch_repl_line(runner, command, cast(Any, state))


def repl_line_has_continuation(line: str) -> bool:
    """Return whether a script line has a REPL continuation marker."""
    from .shell import line_has_continuation

    return line_has_continuation(line)


def repl_remove_line_continuation(line: str) -> str:
    """Remove a REPL continuation marker from a script line."""
    from .shell import remove_line_continuation

    return remove_line_continuation(line)


def repl_split_command_sequence(line: str) -> list[str]:
    """Split a logical REPL script line into commands."""
    from .shell import split_command_sequence

    return split_command_sequence(line)


def hydrate_persistent_secrets(db: EventStore, registry: PluginRegistry) -> None:
    """Load persisted DB secrets back into the registry secret/variable stores."""
    for secret_ref, value in db.stored_secrets():
        registry.secrets.remember(secret_ref, value)
        registry.varstore.set(secret_ref.name, secret_ref.ref)


def dispatch_project_command(runner: Runner, state: ResourceState, tokens: list[str]) -> None:
    """Handle project management commands in the REPL."""
    if not tokens:
        print("usage: project list, project info, project new name=<name> [--encrypt], project use name=<name>")
        return
    handler = PROJECT_COMMAND_HANDLERS.get(tokens[0])
    if handler is None:
        print("usage: project list, project info, project new name=<name> [--encrypt], project use name=<name>")
        return
    handler(runner, state, tokens[1:])


ProjectCommandHandler = Callable[[Runner, ResourceState, list[str]], None]


def project_list_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Print known projects."""
    del state, args
    print_project_list(runner)


def project_info_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Print active project details."""
    del state, args
    print_project_info(runner)


def project_new_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Create a project."""
    del runner, state
    name = selector_value(args, "name") or positional_value(args)
    if not name:
        raise ValueError("usage: project new name=<name> [--encrypt]")
    paths = create_project(name)
    passphrase = prompt_database_passphrase(paths.database, creating=True) if "--encrypt" in args else None
    EventStore(paths.database, passphrase=passphrase)
    print(f"created project={paths.name} path={paths.path}")


def project_use_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Switch active project."""
    name = selector_value(args, "name") or positional_value(args)
    if not name:
        raise ValueError("usage: project use name=<name> [--force]")
    switch_project(runner, state, require_project(name), force="--force" in args)


PROJECT_COMMAND_HANDLERS: dict[str, ProjectCommandHandler] = {
    "info": project_info_command,
    "list": project_list_command,
    "new": project_new_command,
    "use": project_use_command,
}


def selector_value(tokens: list[str], key: str) -> str | None:
    """Return `key=value` from tokenized selectors."""
    prefix = f"{key}="
    for token in tokens:
        if token.startswith(prefix):
            return token.split("=", 1)[1]
    return None


def positional_value(tokens: list[str]) -> str | None:
    """Return the first non-flag, non-selector token."""
    for token in tokens:
        if not token.startswith("--") and "=" not in token:
            return token
    return None


def print_project_list(runner: Runner) -> None:
    """Print known projects with the active project marked."""
    active = active_project_name(runner)
    rows = list_projects()
    if not rows:
        print("no projects")
        return
    for project in rows:
        marker = "*" if project.name == active else " "
        exists = "db" if project.database.exists() else "no-db"
        print(f"{marker} {project.name}\t{exists}\t{project.path}")


def print_project_info(runner: Runner) -> None:
    """Print the active project or ad hoc database path."""
    project = runner.project if isinstance(runner.project, ProjectPaths) else None
    if project is None:
        print(f"project=<none> db={runner.db.path}")
        return
    print(f"project={project.name}")
    print(f"path={project.path}")
    print(f"db={project.database}")
    print(f"config={project.config}")
    print(f"history={project.history}")


def active_project_name(runner: Runner) -> str | None:
    """Return active project name, if any."""
    project = runner.project if isinstance(runner.project, ProjectPaths) else None
    return project.name if project else None


def switch_project(runner: Runner, state: ResourceState, project: ProjectPaths, *, force: bool = False) -> None:
    """Switch the active DB/config/history to another project if idle."""
    active_jobs = runner.db.jobs(active_only=True)
    if active_jobs:
        if not force:
            raise ValueError(
                f"cannot switch to project={project.name} while {len(active_jobs)} job(s) are active; "
                f"use `project use name={project.name} --force` to hard-stop them and switch anyway"
            )
        stop_active_jobs_for_project_switch(runner, active_jobs)
    load_database(runner, project.database)
    runner.project = project
    state.history_path = project.history
    runner.registry.varstore.values.clear()
    if project.config.exists():
        apply_config(runner, project.config)
    hydrate_persistent_secrets(runner.db, runner.registry)
    if state.completer is not None:
        state.completer.db = runner.db
    print(f"using project={project.name}")


def stop_active_jobs_for_project_switch(runner: Runner, jobs) -> None:
    """Hard-stop active jobs before switching projects."""
    stopped: list[dict[str, object]] = []
    for job in jobs:
        pid = job["pid"]
        if pid is not None:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise ValueError(f"cannot stop job {job['id']} pid={pid}: permission denied") from exc
        runner.db.finish_job(int(job["id"]), "killed")
        stopped.append(
            {
                "job_id": int(job["id"]),
                "serial": str(job["serial"]) if job["serial"] is not None else "",
                "pid": int(pid) if pid is not None else None,
                "command_line": str(job["command_line"]),
            }
        )
    runner.events.publish(
        "project.switch.force_stopped",
        {"jobs": stopped, "count": len(stopped)},
        "framework",
    )
    print(f"stopped {len(jobs)} active job(s)")


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
DEFAULT_LOAD_RESOURCE_KEYS = {"config", "db", "history"}


def parse_load_spec(spec: str) -> tuple[bool, str]:
    """Parse built-in load options while keeping resource syntax consistent."""
    tokens = shlex.split(spec)
    forced = False
    resource_tokens: list[str] = []
    for token in tokens:
        if token == "--force":
            forced = True
        else:
            resource_tokens.append(token)
    if len(resource_tokens) != 1:
        raise ValueError("usage: load [--force] plugin=<path>, load script=<path>, load db=<path>, load config=<path>, or load history=<path>")
    return forced, resource_tokens[0]


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
DEFAULT_SAVE_RESOURCE_KEYS = {"config", "db", "history"}


def parse_save_spec(spec: str) -> tuple[bool, str]:
    """Parse built-in save options while keeping the resource syntax simple."""
    tokens = shlex.split(spec)
    encrypt = False
    resource_tokens: list[str] = []
    for token in tokens:
        if token == "--encrypt":
            encrypt = True
        else:
            resource_tokens.append(token)
    if len(resource_tokens) != 1:
        raise ValueError("usage: save [--encrypt] db=<path>, save config=<path>, or save history=<path>")
    return encrypt, resource_tokens[0]


def parse_resource_assignment(resource: str) -> tuple[str, str]:
    """Split a resource key=value string."""
    key, separator, value = resource.partition("=")
    if not separator:
        return resource, ""
    return key, value


def save_database(runner: Runner, path: Path, *, encrypt: bool = False) -> None:
    """Copy the active SQLite database to a snapshot file."""
    maintenance = runner.maintenance
    if encrypt:
        passphrase = prompt_database_passphrase(path, creating=True)
        export_encrypted_database(
            maintenance.path,
            path,
            passphrase,
            source_passphrase=maintenance.passphrase,
        )
    elif maintenance.encrypted:
        if maintenance.passphrase is None:
            raise RuntimeError("encrypted database is missing its in-memory passphrase")
        export_plaintext_database(maintenance.path, path, source_passphrase=maintenance.passphrase)
    else:
        copy_sqlite_database(maintenance.path, path)
    print(f"saved db={path}")


def load_database(runner: Runner, path: Path) -> None:
    """Switch the runner to a different SQLite database file."""
    passphrase = None
    if database_appears_encrypted(path):
        passphrase = prompt_database_passphrase(path, creating=False)
    runner.db = EventStore(path, passphrase=passphrase)
    runner.db.mark_stale_jobs()
    print(f"loaded db={path}")


def copy_sqlite_database(source: Path, destination: Path) -> None:
    """Use SQLite backup API instead of copying files around WAL state."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with EventStore(source).connect() as source_conn:
        with EventStore(destination).connect() as dest_conn:
            source_conn.backup(dest_conn)


def prompt_database_passphrase(path: Path, *, creating: bool) -> str:
    """Prompt for a database passphrase without ever storing it on disk."""
    action = "Create passphrase for encrypted database" if creating else "Passphrase for encrypted database"
    return getpass.getpass(f"{action} {path}: ")


def save_config(runner: Runner, path: Path) -> None:
    """Persist session variables as TOML or JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".toml":
        text = dump_variables_toml(runner.registry.varstore.values)
    else:
        text = json.dumps(runner.registry.varstore.values, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    print(f"saved config={path}")


def load_config(runner: Runner, path: Path) -> None:
    """Replace session variables from a TOML table or JSON object."""
    apply_config(runner, path)
    print(f"loaded config={path}")


def apply_config(runner: Runner, path: Path) -> None:
    """Replace session variables from config without user-facing output."""
    data = load_data_file(path)
    values = data.get("variables", data)
    if not isinstance(values, dict):
        raise ValueError(f"{path} variables must be an object/table")
    runner.registry.varstore.values.clear()
    for key, value in values.items():
        runner.registry.varstore.set(str(key), value)


def save_history(state: ResourceState, path: Path) -> None:
    """Save current-session history lines to a script-friendly file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(state.session_history)
    path.write_text(f"{text}\n" if text else "")
    print(f"saved history={path}")


def load_history(state: ResourceState, path: Path) -> None:
    """Load a history file as the current session history and append target."""
    state.history_path = path
    state.session_history = path.read_text().splitlines() if path.exists() else []
    print(f"loaded history={path}")


def publish_resource_loaded(
    runner: Runner,
    resource_type: str,
    *,
    path: Path,
    details: dict[str, object] | None = None,
) -> Event:
    """Audit one explicitly loaded resource and return the persisted event."""
    serial = new_run_id(resource_type)
    payload: dict[str, object] = {
        "serial": serial,
        "resource_type": resource_type,
        "path": str(path),
    }
    if details:
        payload.update(details)
    return runner.events.publish(f"resource.{resource_type}.loaded", payload, "framework")


def plugin_manifest_audit_details(plugin_path: Path) -> dict[str, object]:
    """Return manifest metadata for plugin-load audit events."""
    manifest_path = plugin_path / "bywaf.plugin.toml"
    if not manifest_path.exists():
        return {"manifest": None, "manifest_sha256": None}
    manifest = parse_plugin_manifest(manifest_path)
    return {
        "manifest": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "traits": {
            "native": manifest.native,
            "library_backed": manifest.library_backed,
            "process_wrapped": manifest.process_wrapped,
            "service": manifest.service,
        },
        "roles": list(manifest.roles),
        "capabilities": {
            name: list(capabilities)
            for name, capabilities in sorted(manifest.commandlet_capabilities.items())
        },
        "secret_options": {
            name: list(options)
            for name, options in sorted(manifest.commandlet_secret_options.items())
            if options
        },
    }


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hash for one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_explicit_path(value: str) -> bool:
    """Return True when resource resolution should not prepend a root."""
    return (
        value.startswith(("./", "../", "~/"))
        or Path(value).is_absolute()
    )


def resolve_resource_path(value: str, root: Path, default: Path | None = None) -> Path:
    """Resolve load/save resource names consistently.

    Plain plugin names use the plugin root; most other resource roots are `.`.
    Explicit paths such as `./x`, `../x`, `~/x`, and `/x` are used directly.
    """
    if not value:
        if default is None:
            raise ValueError("resource path is required")
        return default.expanduser()
    path = Path(value).expanduser()
    if is_explicit_path(value):
        return path
    return root / path


def run_script(runner: Runner, path: Path, state: ResourceState | None = None) -> None:
    """Run one command expression per non-comment script line."""
    state = state or default_resource_state(runner)
    commands = script_commands(path)
    event = publish_resource_loaded(
        runner,
        "script",
        path=path,
        details={"commands": len(commands)},
    )
    serial = str(event.payload["serial"])
    print(f"loaded script={path} serial={serial}")
    for line_number, command in commands:
        runner.events.publish(
            "resource.script.command",
            {
                "serial": serial,
                "resource_type": "script",
                "path": str(path),
                "line": line_number,
                "command": command,
            },
            "framework",
        )
        print(f"{path}:{line_number}: {command}")
        if dispatch_script_command(runner, command, state) == "exit":
            return


def script_commands(path: Path) -> list[tuple[int, str]]:
    """Parse a Bywaf script file into `(line_number, command)` tuples."""
    commands: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = strip_inline_comment(raw_line).rstrip()
        if not buffer and not line.strip():
            continue
        if not buffer:
            start_line = line_number
        if repl_line_has_continuation(line):
            buffer.append(repl_remove_line_continuation(line))
            continue
        buffer.append(line)
        logical_line = "\n".join(buffer).strip()
        for command in repl_split_command_sequence(logical_line):
            commands.append((start_line, command))
        buffer = []
    if buffer:
        logical_line = "\n".join(buffer).strip()
        for command in repl_split_command_sequence(logical_line):
            commands.append((start_line, command))
    return commands

def strip_inline_comment(line: str) -> str:
    """Remove shell-style `#` comments while preserving quoted hashes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in ("'", '"'):
            quote = None if quote == char else char if quote is None else quote
            continue
        if char == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line
