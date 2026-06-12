"""Maintenance and variable store protocols.

Used by:
- command contexts, runners, runtime plugins, and tests that depend on
  storage protocol boundaries.
- maintainers keeping persistence interfaces decoupled from concrete stores.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class MaintenanceStoreProtocol(Protocol):
    """Database maintenance operations used by privileged framework code."""

    path: Path

    @property
    def passphrase(self) -> str | None:
        """Return the in-memory DB passphrase, when one is active."""
        ...

    @passphrase.setter
    def passphrase(self, value: str | None) -> None:
        """Replace the active DB passphrase after a rekey."""
        ...

    @property
    def encrypted(self) -> bool:
        """Return whether the active store is encrypted."""
        ...

    def checkpoint(self) -> None:
        """Flush pending write-ahead-log state during clean shutdown."""
        ...

    def vacuum(self) -> None:
        """Rebuild storage to reclaim free pages."""
        ...

    def rekey(self, new_passphrase: str) -> None:
        """Change the encryption key for an encrypted store."""
        ...

    def table_counts(self) -> dict[str, int]:
        """Return table-level row counts for status output."""
        ...


@runtime_checkable
class VariableStoreProtocol(Protocol):
    """Session variable storage used by config and completion code."""

    def set(self, key: str, value: Any) -> None:
        """Persist one variable value."""
        ...

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return one variable value."""
        ...

    def update_prefixed(self, prefix: str, values: dict[str, Any]) -> None:
        """Load a set of values under a commandlet/plugin prefix."""
        ...

    def names(self) -> list[str]:
        """Return variable names for completion."""
        ...

    def items(self) -> list[tuple[str, str]]:
        """Return all variable key/value pairs."""
        ...
