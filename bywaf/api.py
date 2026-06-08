"""Programmatic API for embedding Bywaf sessions.

Provides BywafSession for opening databases, running commands, and starting
background commandlets without going through the CLI or interactive REPL.

Used by:
- library callers: automate Bywaf workflows from Python code.
- API tests: validate command execution and encrypted database opening."""


from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings
from .db import EventStore, database_appears_encrypted
from .event import Event
from .registry import PluginRegistry
from .runner import Runner
from .stores import EventStoreProtocol, MaintenanceStoreProtocol, RuntimeStoreProtocol
from .toml_support import dump_variables_toml, load_data_file


@dataclass(slots=True)
class BywafSession:
    """Small public facade for REPL, GUI, web, and test clients.

    This represents an embedded Bywaf runtime session.
    Constructed by: `BywafSession.open()`.
    Used by: external Python callers and API tests to run command text, inspect
    jobs/events, and export/import state without driving the interactive shell.
    """

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
        force_plugins: bool = False,
    ) -> "BywafSession":
        """Open a Bywaf session without invoking the interactive shell."""
        database_path = Path(database) if database is not None else Settings().database
        db_passphrase = passphrase
        if db_passphrase is None and (encrypted or database_appears_encrypted(database_path)):
            raise ValueError("encrypted database requires an explicit passphrase")
        registry = PluginRegistry.discover()
        if plugin_root and plugin_config:
            # External filesystem plugins share the discovered registry's
            # varstore so variables set before loading still apply afterward.
            filesystem = PluginRegistry.from_config(
                Path(plugin_root),
                Path(plugin_config),
                varstore=registry.varstore,
                forced=force_plugins,
            )
            registry.plugins.update(filesystem.plugins)
        return cls(Runner(EventStore(database_path, passphrase=db_passphrase), registry))

    @property
    def db(self) -> EventStore:
        """Return the concrete active store for backward compatibility."""
        return self.runner.db

    @property
    def event_store(self) -> EventStoreProtocol:
        """Return the active event/audit store."""
        return self.runner.events

    @property
    def runtime_store(self) -> RuntimeStoreProtocol:
        """Return the active runtime metadata store."""
        return self.runner.runtime

    @property
    def maintenance_store(self) -> MaintenanceStoreProtocol:
        """Return the active maintenance store."""
        return self.runner.maintenance

    @property
    def registry(self) -> PluginRegistry:
        """Return the active plugin registry."""
        return self.runner.registry

    def run(self, command: str) -> list[Event]:
        """Run a commandlet expression in the foreground."""
        # The embedding API intentionally accepts the same commandlet syntax as
        # the REPL, keeping automation and interactive use aligned.
        return self.runner.execute(command)

    def run_background(self, command: str) -> Event:
        """Start a commandlet expression as a background job."""
        return self.runner.start_background(command)

    def jobs(self):
        """Return known background and foreground job rows."""
        return self.runtime_store.jobs()

    def events(
        self,
        *,
        topic: str | None = None,
        run: str | None = None,
        pipeline: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        """Return events filtered by topic, pipeline step, or pipeline."""
        return self.event_store.events_matching(
            topic=topic,
            command_run_id=run,
            pipeline_id=pipeline,
            limit=limit,
        )

    def topics(self) -> list[str]:
        """Return event topics in the active database."""
        return self.event_store.topics()

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
        """Save session variables to TOML or JSON."""
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if config_path.suffix == ".toml":
            # Prefer TOML for user-edited config, JSON for callers that want a
            # machine-native structure.
            text = dump_variables_toml(self.registry.varstore.values)
        else:
            text = json.dumps(self.registry.varstore.values, indent=2, sort_keys=True) + "\n"
        config_path.write_text(text, encoding="utf-8")

    def load_config(self, path: str | Path) -> None:
        """Load session variables from TOML or JSON."""
        data = load_data_file(Path(path))
        values = data.get("variables", data)
        if not isinstance(values, dict):
            raise ValueError(f"{path} variables must be an object/table")
        # Match REPL config load semantics: replace, do not merge.
        self.registry.varstore.values.clear()
        for key, value in values.items():
            self.registry.varstore.set(str(key), value)

    def checkpoint(self) -> None:
        """Checkpoint the active SQLite database."""
        self.maintenance_store.checkpoint()
