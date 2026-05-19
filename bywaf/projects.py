"""Project directory helpers.

A Bywaf project is one isolated working directory containing its own database,
artifact database, config, and history. The default layout is intentionally
directory-based instead of adding `project_id` to every table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class ProjectPaths:
    """Resolved filesystem paths for one Bywaf project."""

    name: str
    root: Path
    path: Path
    database: Path
    config: Path
    history: Path


def projects_root() -> Path:
    """Return the user-local project root."""
    return Path.home() / ".bywaf" / "projects"


def validate_project_name(name: str) -> str:
    """Validate a project name for use as one path segment."""
    if not PROJECT_NAME_RE.fullmatch(name):
        raise ValueError("project names may contain letters, digits, dot, dash, and underscore")
    return name


def project_paths(name: str, *, root: Path | None = None) -> ProjectPaths:
    """Return conventional paths for one project name."""
    clean_name = validate_project_name(name)
    base = root or projects_root()
    path = base / clean_name
    return ProjectPaths(
        name=clean_name,
        root=base,
        path=path,
        database=path / "bywaf.sqlite3",
        config=path / "config.toml",
        history=path / "history.bywaf",
    )


def list_projects(*, root: Path | None = None) -> list[ProjectPaths]:
    """Return known project directories in stable order."""
    base = root or projects_root()
    if not base.exists():
        return []
    return [
        project_paths(path.name, root=base)
        for path in sorted(base.iterdir())
        if path.is_dir() and PROJECT_NAME_RE.fullmatch(path.name)
    ]


def create_project(name: str, *, root: Path | None = None) -> ProjectPaths:
    """Create a new project directory with placeholder config/history files."""
    paths = project_paths(name, root=root)
    if paths.path.exists():
        raise FileExistsError(f"project already exists: {paths.name}")
    paths.path.mkdir(parents=True)
    paths.config.write_text("[variables]\n", encoding="utf-8")
    paths.history.write_text("", encoding="utf-8")
    return paths


def require_project(name: str, *, root: Path | None = None) -> ProjectPaths:
    """Return an existing project or raise a clear error."""
    paths = project_paths(name, root=root)
    if not paths.path.exists():
        raise FileNotFoundError(f"project does not exist: {paths.name}")
    return paths
