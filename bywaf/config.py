"""Runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    state_dir: Path = Path(".bywaf")
    database: Path = Path(".bywaf/bywaf.sqlite3")
    config: Path = Path(".bywaf/config.json")
    history: Path = Path(".bywaf/history.bywaf")
    plugin_dir: Path = Path(".bywaf/plugins")
    script_dir: Path = Path(".bywaf/scripts")
    database_dir: Path = Path(".bywaf/db")
    config_dir: Path = Path(".bywaf/config")
    plugin_package: str = "bywaf.plugins"
    poll_interval_seconds: float = 0.25


def default_settings() -> Settings:
    """Return default process-local settings."""
    return Settings()
