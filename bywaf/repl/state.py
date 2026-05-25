"""Shared state protocol for REPL resource helpers.

Provides ResourceState and default resource-state construction without making
resource modules import the shell implementation at module import time.

Used by:
- REPL resource, project, persistence, and script helpers: type shared state.
- script execution: create default shell state for non-interactive use.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import Protocol

from ..db import EventStore
from ..registry import PluginRegistry
from ..runner import Runner


class ResourceState(Protocol):
    """Mutable shell state used by resource commands."""

    history_path: Path
    session_history: list[str]
    completer: Any | None


def default_resource_state(runner: Runner) -> ResourceState:
    """Create default resource state without importing repl at module load time."""
    # Import lazily to avoid a circular import: shell imports resources, and
    # resources need a fallback state for non-interactive script execution.
    from .shell import new_shell_state

    return new_shell_state(runner)


def hydrate_persistent_secrets(db: EventStore, registry: PluginRegistry) -> None:
    """Load persisted DB secrets back into the registry secret/variable stores."""
    for secret_ref, value in db.stored_secrets():
        # VarStore holds the secret reference, not the cleartext; SecretStore
        # keeps the cleartext available for commandlet execution.
        registry.secrets.remember(secret_ref, value)
        registry.varstore.set(secret_ref.name, secret_ref.ref)
