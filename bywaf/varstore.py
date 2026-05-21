"""Variable storage and interpolation helpers.

Provides scoped variable storage, lookup, assignment, and expansion behavior for
commandlets and framework-level variables.

Used by:
- command parser, REPL vars, and plugin contexts: resolve runtime variables.
- tests: verify scoping and interpolation behavior."""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class VarStore:
    """String-valued session variable storage shared by commandlets."""

    values: dict[str, str] = field(default_factory=dict)

    def set(self, key: str, value: Any) -> None:
        """Store values as strings to keep config serialization simple."""
        self.values[key] = str(value)

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return a variable or a caller-provided fallback."""
        return self.values.get(key, default)

    def update_prefixed(self, prefix: str, values: dict[str, Any]) -> None:
        """Load plugin defaults under `<commandlet>.<name>` keys."""
        for key, value in values.items():
            self.set(f"{prefix}.{key}", value)

    def names(self) -> list[str]:
        """Return variable names for completion."""
        return sorted(self.values)

    def items(self) -> list[tuple[str, str]]:
        """Return sorted key/value pairs for stable display and tests."""
        return sorted(self.values.items())


class ScopedVarStore:
    """Namespace-limited view of VarStore exposed to plugins.

    Plugins read and write unqualified local names such as `timeout`; the
    wrapper stores them as `<scope>.timeout` in the underlying VarStore. Global
    variables are intentionally opt-in by name and cannot be enumerated through
    this API.
    """

    __slots__ = ("__store", "scope", "__run_values")

    def __init__(
        self,
        store: VarStore,
        scope: str,
        run_values: dict[str, str] | None = None,
    ) -> None:
        self.__store = store
        self.scope = scope
        self.__run_values = run_values or {}

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return a scoped variable value."""
        scoped = self.scoped_key(key)
        if scoped in self.__run_values:
            return self.__run_values[scoped]
        return self.__store.get(scoped, default)

    def set(self, key: str, value: Any) -> None:
        """Set a scoped variable value."""
        self.__store.set(self.scoped_key(key), value)

    def get_global(self, key: str, default: str | None = None) -> str | None:
        """Read an explicitly global variable such as `global.proxy`."""
        scoped = f"global.{key}"
        if scoped in self.__run_values:
            return self.__run_values[scoped]
        return self.__store.get(scoped, default)

    def scoped_key(self, key: str) -> str:
        """Convert a local variable name to its fully-qualified storage key."""
        if "." in key:
            raise ValueError("plugin variables must use unqualified names")
        return f"{self.scope}.{key}"
