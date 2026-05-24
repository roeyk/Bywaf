"""Resource spec parsing and path resolution.

Provides default resource paths, parsing for plugin load specs, and path
resolution rules that preserve project defaults and explicit paths.

Used by:
- resource facade: route `plugin load=...` commands to concrete handlers.
- CLI startup and tests: resolve default database, config, history, and script paths.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from ..config import Settings


DEFAULT_SETTINGS = Settings()
DEFAULT_DATABASE = DEFAULT_SETTINGS.database
DEFAULT_CONFIG = DEFAULT_SETTINGS.config
DEFAULT_HISTORY = DEFAULT_SETTINGS.history
DEFAULT_PLUGIN_DIR = DEFAULT_SETTINGS.plugin_dir
DEFAULT_SCRIPT_DIR = DEFAULT_SETTINGS.script_dir
DEFAULT_DATABASE_DIR = DEFAULT_SETTINGS.database_dir
DEFAULT_CONFIG_DIR = DEFAULT_SETTINGS.config_dir
DEFAULT_LOAD_RESOURCE_KEYS: set[str] = set()


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
        raise ValueError("usage: plugin load=<path> [--force]")
    return forced, resource_tokens[0]


DEFAULT_SAVE_RESOURCE_KEYS: set[str] = set()


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
        raise ValueError("usage: config save file=<path> [--encrypt], history save file=<path> [--encrypt], or script save file=<path> [--encrypt]")
    return encrypt, resource_tokens[0]


def parse_resource_assignment(resource: str) -> tuple[str, str]:
    """Split a resource key=value string."""
    key, separator, value = resource.partition("=")
    if not separator:
        return resource, ""
    return key, value


def is_explicit_path(value: str) -> bool:
    """Return True when resource resolution should not prepend a root."""
    return (
        value.startswith(("./", "../", "~/"))
        or Path(value).is_absolute()
    )


def resolve_resource_path(value: str, root: Path, default: Path | None = None) -> Path:
    """Resolve resource names consistently.

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
