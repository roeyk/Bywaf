"""Session variable storage."""

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
