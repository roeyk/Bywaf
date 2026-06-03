"""First-run setup helpers.

Provides the explicit `bywaf --setup` path and first-run configuration
detection without making setup mandatory for ad hoc exploration.

Used by:
- bywaf.app: route explicit setup and show the interactive first-run notice.
- tests: verify user-local setup state under an isolated HOME.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

from .db import EventStore
from .projects import ProjectPaths, create_project, project_paths, projects_root


DEFAULT_PROJECT_NAME = "default"
USER_CONFIG_TEMPLATE = """# Bywaf user configuration.
# Project data lives under ~/.bywaf/projects/<name>/.

[setup]
version = 1
default_project = "default"
"""


@dataclass(frozen=True, slots=True)
class SetupResult:
    """Paths created or confirmed by one setup run."""

    config: Path
    project: ProjectPaths
    created_config: bool
    created_project: bool
    recorded_event: bool


def user_state_root() -> Path:
    """Return the durable per-user Bywaf state directory."""
    return Path.home() / ".bywaf"


def user_config_path() -> Path:
    """Return the durable per-user setup/configuration file path."""
    return user_state_root() / "config.toml"


def setup_missing() -> bool:
    """Return whether first-run setup state is absent."""
    return not user_config_path().exists()


def interactive_stdio() -> bool:
    """Return whether the current process can show friendly interactive text."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def first_run_notice_needed(*, quiet: bool, interactive: bool | None = None) -> bool:
    """Return whether startup should show the friendly first-run setup notice."""
    if quiet or not setup_missing():
        return False
    return interactive_stdio() if interactive is None else interactive


def print_first_run_notice() -> None:
    """Print the interactive first-run setup notice."""
    print("No Bywaf configuration found.")
    print("Run `bywaf --setup` to create one, or continue with defaults.")


def run_setup(*, project_name: str = DEFAULT_PROJECT_NAME, output: bool = True) -> SetupResult:
    """Create durable user setup files and a default project if needed."""
    root = user_state_root()
    config = user_config_path()
    root.mkdir(parents=True, exist_ok=True)
    created_config = not config.exists()
    if created_config:
        config.write_text(USER_CONFIG_TEMPLATE, encoding="utf-8")

    projects_root().mkdir(parents=True, exist_ok=True)
    project = project_paths(project_name)
    created_project = not project.path.exists()
    if created_project:
        project = create_project(project_name)

    recorded_event = False
    if project.database.exists() or created_project:
        db = EventStore(project.database)
        db.publish(
            "setup.completed",
            {
                "config": str(config),
                "project": project.name,
                "project_path": str(project.path),
                "created_config": created_config,
                "created_project": created_project,
            },
            "framework",
        )
        recorded_event = True

    result = SetupResult(
        config=config,
        project=project,
        created_config=created_config,
        created_project=created_project,
        recorded_event=recorded_event,
    )
    if output:
        print_setup_result(result)
    return result


def print_setup_result(result: SetupResult) -> None:
    """Print a compact operator-facing setup summary."""
    config_status = "created" if result.created_config else "exists"
    project_status = "created" if result.created_project else "exists"
    print(f"Bywaf configuration {config_status}: {result.config}")
    print(f"Default project {project_status}: {result.project.path}")
    print(f"Project database: {result.project.database}")
    print("Use `bywaf project=default` to start in this project.")
