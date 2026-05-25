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
        """Load plugin defaults under `<commandlet-address>.<name>` keys."""
        for key, value in values.items():
            scoped = f"{prefix}.{key}"
            if scoped not in self.values:
                self.set(scoped, value)

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

    __slots__ = ("__store", "scope", "provider_scope", "__provider_variables", "__run_values")

    def __init__(
        self,
        store: VarStore,
        scope: str,
        provider_scope: str | None = None,
        provider_variables: set[str] | frozenset[str] | None = None,
        run_values: dict[str, str] | None = None,
    ) -> None:
        self.__store = store
        self.scope = scope
        self.provider_scope = provider_scope or provider_scope_for(scope)
        self.__provider_variables = frozenset(provider_variables or ())
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

    def get_provider(self, key: str, default: str | None = None) -> str | None:
        """Read an explicitly provider-scoped variable such as `http/repo.proxy`."""
        if key not in self.__provider_variables:
            # Provider variables cross the commandlet boundary, so manifests
            # must declare them before plugin code can read them.
            raise PermissionError(f"provider variable not declared for this commandlet: {key}")
        scoped = provider_scoped_key(self.provider_scope, key)
        if scoped in self.__run_values:
            return self.__run_values[scoped]
        return self.__store.get(scoped, default)

    def scoped_key(self, key: str) -> str:
        """Convert a local variable name to its fully-qualified storage key."""
        if "/" in key or "." in key:
            raise ValueError("plugin variables must use unqualified names")
        return f"{self.scope}.{key}"


def provider_scope_for(scope: str) -> str:
    """Return the provider path that owns one commandlet variable scope."""
    if "/" not in scope:
        return scope
    # Commandlet variables live at catalog/path/commandlet.name. Provider
    # variables intentionally stop one level above the commandlet.
    return scope.rsplit("/", 1)[0]


def provider_scoped_key(provider_scope: str, key: str) -> str:
    """Return a provider-scoped variable key."""
    if not provider_scope or "." in provider_scope or "//" in provider_scope:
        raise ValueError("provider scope must be a slash-delimited catalog path")
    if "/" in key or "." in key:
        raise ValueError("provider variables must use unqualified names")
    return f"{provider_scope}.{key}"
