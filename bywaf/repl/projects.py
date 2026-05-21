"""Project commands for the REPL resource layer.

Provides `project` command dispatch, project listing/creation/switching, and
forced active-job cleanup before switching project databases.

Used by:
- bywaf.repl.commands: implements the `project` built-in.
- resource facade: re-exports project helpers for compatibility.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable

from ..db import EventStore
from ..projects import ProjectPaths, create_project, list_projects, require_project
from ..runner import Runner
from .persistence import apply_config, load_database, prompt_database_passphrase
from .state import ResourceState, hydrate_persistent_secrets


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
