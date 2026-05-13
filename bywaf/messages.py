"""Typed payload helpers for common event shapes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any, TypeVar

T = TypeVar("T", bound="Message")


@dataclass(frozen=True, slots=True)
class Message:
    """Base class for structured event payloads stored in SQLite."""

    run_id: str

    def to_json(self) -> str:
        """Serialize the payload in a deterministic form for storage/tests."""

        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls: type[T], payload: str) -> T:
        """Deserialize a payload while ignoring fields unknown to this class."""

        data = json.loads(payload)
        names = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in names})

    def to_payload(self) -> dict[str, Any]:
        """Return a plain dictionary suitable for `EventStore.publish`."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class Host(Message):
    """Host discovery payload."""

    host: str
    status: str = "candidate"


@dataclass(frozen=True, slots=True)
class OpenPorts(Message):
    """Port discovery payload for a single host."""

    host: str
    ports: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Progress(Message):
    """Progress payload for long-running commandlets."""

    status: str
    total: int
    completed: int

    @property
    def percent(self) -> int:
        """Return integer completion percentage without dividing by zero."""

        if self.total <= 0:
            return 0
        return int((self.completed / self.total) * 100)
