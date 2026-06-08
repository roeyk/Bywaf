"""Project commands for the REPL resource layer.

Provides `project` command dispatch, project listing/creation/switching,
project archiving, and forced active-job cleanup before switching databases.

Used by:
- bywaf.repl.commands: implements the `project` built-in.
- resource facade: re-exports project helpers for compatibility.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable
from pathlib import Path

from ..db import EventStore
from ..command.names import PROJECT_ACTIONS, PROJECT_ARCHIVE, PROJECT_EXPORT, PROJECT_INFO, PROJECT_LIST, PROJECT_NEW, PROJECT_USE
from ..projects import ProjectPaths, create_project, list_projects, require_project
from ..runner import Runner
from .persistence import apply_config, load_database, prompt_database_passphrase
from .project_archive import archive_project
from .state import ResourceState, hydrate_persistent_secrets


def dispatch_project_command(runner: Runner, state: ResourceState, tokens: list[str]) -> None:
    """Handle project management commands in the REPL."""
    if not tokens:
        print_project_usage()
        return
    # This lookup uses PROJECT_COMMAND_HANDLERS, defined below, in place of an
    # if/elif ladder over project subcommands.
    handler = PROJECT_COMMAND_HANDLERS.get(tokens[0])
    if handler is None:
        print_project_usage()
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
    # Create the database immediately so `project use` can switch without a
    # separate first-run initialization path.
    passphrase = prompt_database_passphrase(paths.database, creating=True) if "--encrypt" in args else None
    EventStore(paths.database, passphrase=passphrase)
    print(f"created project={paths.name} path={paths.path}")


def project_use_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Switch active project."""
    name = selector_value(args, "name") or positional_value(args)
    if not name:
        raise ValueError("usage: project use name=<name> [--force]")
    switch_project(runner, state, require_project(name), force="--force" in args)


def project_archive_command(runner: Runner, state: ResourceState, args: list[str]) -> None:
    """Archive active project-owned state."""
    del state
    output = selector_value(args, "file") or positional_value(args)
    if not output:
        raise ValueError("usage: project archive file=<path> [--encrypt]")
    result = archive_project(runner, Path(output).expanduser(), encrypt="--encrypt" in args)
    encrypted = "true" if result["encrypted"] else "false"
    print(
        f"archived project={result['project']} file={result['file']} "
        f"files={result['files']} encrypted={encrypted} event={result['event_id']}"
    )


# Project subcommands mutate or inspect project state outside ordinary plugin
# execution. handle_project_command() uses this dispatch table so supported actions stay
# synchronized with PROJECT_ACTIONS and completion/help.
PROJECT_COMMAND_HANDLERS: dict[str, ProjectCommandHandler] = {
    PROJECT_ARCHIVE: project_archive_command,
    PROJECT_EXPORT: project_archive_command,
    PROJECT_INFO: project_info_command,
    PROJECT_LIST: project_list_command,
    PROJECT_NEW: project_new_command,
    PROJECT_USE: project_use_command,
}

# Keep the documented action tuple and dispatch table synchronized. This makes
# completion/help drift visible during import/tests instead of at runtime.
assert tuple(PROJECT_COMMAND_HANDLERS) == PROJECT_ACTIONS


def print_project_usage() -> None:
    """Print supported project subcommands."""
    print(
        "usage: project list, project info, project new name=<name> [--encrypt], "
        "project use name=<name> [--force], project archive file=<path> [--encrypt], "
        "project export file=<path> [--encrypt]"
    )


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
    # Project switching is a coordinated DB/config/history boundary change.
    # Load the database first so subsequent config and secret hydration target
    # the new project.
    load_database(runner, project.database, force=True)
    runner.project = project
    state.history_path = project.history
    # Project switch resets runtime configuration to the target project's config.
    # It intentionally does not merge with variables from the previous project.
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
                # Forced project switch is a database boundary change. Child
                # processes must be stopped before the runner points elsewhere.
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                # The stale-job cleanup below will still mark the job killed.
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
