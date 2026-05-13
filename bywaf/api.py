"""Public library facade for embedding Bywaf."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings
from .db import EventStore, database_appears_encrypted
from .events import Event
from .registry import PluginRegistry
from .runner import Runner


@dataclass(slots=True)
class BywafSession:
    """Small public facade for REPL, GUI, web, and test clients."""

    runner: Runner

    @classmethod
    def open(
        cls,
        database: str | Path | None = None,
        *,
        encrypted: bool = False,
        passphrase: str | None = None,
        plugin_root: str | Path | None = None,
        plugin_config: str | Path | None = None,
    ) -> "BywafSession":
        """Open a Bywaf session without invoking the interactive shell."""
        database_path = Path(database) if database is not None else Settings().database
        db_passphrase = passphrase
        if db_passphrase is None and (encrypted or database_appears_encrypted(database_path)):
            raise ValueError("encrypted database requires an explicit passphrase")
        registry = PluginRegistry.discover()
        if plugin_root and plugin_config:
            filesystem = PluginRegistry.from_config(
                Path(plugin_root),
                Path(plugin_config),
                varstore=registry.varstore,
            )
            registry.plugins.update(filesystem.plugins)
        return cls(Runner(EventStore(database_path, passphrase=db_passphrase), registry))

    @property
    def db(self) -> EventStore:
        """Return the active event store."""
        return self.runner.db

    @property
    def registry(self) -> PluginRegistry:
        """Return the active plugin registry."""
        return self.runner.registry

    def run(self, command: str) -> list[Event]:
        """Run a commandlet expression in the foreground."""
        return self.runner.execute(command)

    def run_background(self, command: str) -> Event:
        """Start a commandlet expression as a background job."""
        return self.runner.start_background(command)

    def jobs(self):
        """Return known background and foreground job rows."""
        return self.db.jobs()

    def events(
        self,
        *,
        topic: str | None = None,
        run: str | None = None,
        pipeline: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events filtered by topic, command run, or pipeline."""
        return self.db.events_matching(
            topic=topic,
            command_run_id=run,
            pipeline_id=pipeline,
            limit=limit,
        )

    def topics(self) -> list[str]:
        """Return event topics in the active database."""
        return self.db.topics()

    def plugins(self) -> list[str]:
        """Return loaded plugin provider names."""
        return self.registry.provider_names()

    def commandlets(self) -> dict[str, list[str]]:
        """Return commandlets grouped by provider."""
        return self.registry.grouped_names()

    def get_var(self, name: str, default: str | None = None) -> str | None:
        """Return a session variable by fully-qualified name."""
        return self.registry.varstore.get(name, default)

    def set_var(self, name: str, value: Any) -> None:
        """Set a session variable by fully-qualified name."""
        self.registry.varstore.set(name, value)

    def save_config(self, path: str | Path) -> None:
        """Save session variables to JSON."""
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(self.registry.varstore.values, indent=2, sort_keys=True) + "\n")

    def load_config(self, path: str | Path) -> None:
        """Load session variables from JSON."""
        values = json.loads(Path(path).read_text())
        if not isinstance(values, dict):
            raise ValueError(f"{path} must contain a JSON object")
        self.registry.varstore.values.clear()
        for key, value in values.items():
            self.registry.varstore.set(str(key), value)

    def checkpoint(self) -> None:
        """Checkpoint the active SQLite database."""
        self.db.checkpoint()
