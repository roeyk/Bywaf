"""Typed payload helpers for common event shapes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any, TypeVar

T = TypeVar("T", bound="Message")


@dataclass(frozen=True, slots=True)
class Message:
    run_id: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls: type[T], payload: str) -> T:
        data = json.loads(payload)
        names = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in names})

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Host(Message):
    host: str
    status: str = "candidate"


@dataclass(frozen=True, slots=True)
class OpenPorts(Message):
    host: str
    ports: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Progress(Message):
    status: str
    total: int
    completed: int

    @property
    def percent(self) -> int:
        if self.total <= 0:
            return 0
        return int((self.completed / self.total) * 100)
