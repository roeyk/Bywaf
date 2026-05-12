"""Session variable storage."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class VarStore:
    values: dict[str, str] = field(default_factory=dict)

    def set(self, key: str, value: Any) -> None:
        self.values[key] = str(value)

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.values.get(key, default)

    def update_prefixed(self, prefix: str, values: dict[str, Any]) -> None:
        for key, value in values.items():
            self.set(f"{prefix}.{key}", value)

    def names(self) -> list[str]:
        return sorted(self.values)

    def items(self) -> list[tuple[str, str]]:
        return sorted(self.values.items())
