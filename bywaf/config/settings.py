"""Default filesystem and runtime configuration values.

Provides Settings, the central set of default paths used by databases, configs,
history files, plugin directories, and script directories.

Used by:
- CLI startup and REPL resource handling: resolve default resource locations.
- tests and packaging checks: assert install-path behavior."""


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    """Filesystem defaults for one Bywaf invocation.

    The project keeps user-writable state under `.bywaf/` so packaged code can
    live elsewhere while databases, configs, plugin overrides, and history stay
    local to the working directory unless the user passes explicit paths.

    Constructed by: `default_settings()` and callers using `Settings()`.
    Used by: CLI, API, project, and resource-loading code when no explicit path
    is supplied.
    """

    # These defaults are intentionally relative. Project mode and explicit CLI
    # paths can redirect them, while ad hoc sessions stay self-contained.
    state_dir: Path = Path(".bywaf")
    database: Path = Path(".bywaf/bywaf.sqlite3")
    config: Path = Path(".bywaf/config.toml")
    history: Path = Path(".bywaf/history.bywaf")
    secret_fingerprint_key: Path = Path(".bywaf/secret-fingerprint.key")
    plugin_dir: Path = Path(".bywaf/plugins")
    script_dir: Path = Path(".bywaf/scripts")
    database_dir: Path = Path(".bywaf/db")
    config_dir: Path = Path(".bywaf/config")
    plugin_package: str = "bywaf.plugins"
    # Polling is used only for lightweight UI/background request loops; long
    # commandlet work should use jobs/events rather than busy waiting here.
    poll_interval_seconds: float = 0.25


def default_settings() -> Settings:
    """Return default process-local settings."""
    return Settings()
