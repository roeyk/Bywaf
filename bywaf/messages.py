"""Shared user-facing message helpers.

Provides small formatting utilities for consistent command output and error
messages where a full table renderer is unnecessary.

Used by:
- commandlets and runtime helpers: keep repeated messages consistent.
- tests: assert stable text for user-visible behavior."""


from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any, TypeVar

T = TypeVar("T", bound="Message")


@dataclass(frozen=True, slots=True)
class Message:
    """Base class for legacy structured event payload helpers.

    This is a small serialization wrapper for message-shaped payload objects.
    Constructed by: message subclasses used by commandlets and tests.
    Used by: `to_payload()`, `to_json()`, and `from_json()` callers that need
    deterministic payload serialization for EventStore-facing data.
    """

    run_id: str

    def to_json(self) -> str:
        """Serialize the payload in a deterministic form for storage/tests.

        Called by: message compatibility tests and any legacy message callers
        that persist JSON directly instead of publishing dictionaries.
        """

        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls: type[T], payload: str) -> T:
        """Deserialize a payload while ignoring fields unknown to this class.

        Called by: compatibility tests and historical message readers that need
        forward-tolerant payload loading.
        """

        data = json.loads(payload)
        names = {field.name for field in fields(cls)}
        # Ignore unknown fields so older message classes can read newer event
        # payloads during upgrades or tests with historical fixtures.
        return cls(**{key: value for key, value in data.items() if key in names})

    def to_payload(self) -> dict[str, Any]:
        """Return a plain dictionary suitable for `EventStore.publish`.

        Called by: commandlets and tests that convert message objects into event
        payload dictionaries.
        """

        return asdict(self)


@dataclass(frozen=True, slots=True)
class Host(Message):
    """Host discovery payload for older host-scanner style messages.

    This represents one discovered host candidate.
    Constructed by: host discovery helpers and compatibility tests.
    Used by: message serialization paths before publishing `host.found`-style
    payloads.
    """

    host: str
    status: str = "candidate"


@dataclass(frozen=True, slots=True)
class OpenPorts(Message):
    """Open-port discovery payload for a single host.

    This represents all open-port observations reported together for one host.
    Constructed by: port-scanner style commandlets and compatibility tests.
    Used by: message serialization paths before discovered port dictionaries
    become event payloads.
    """

    host: str
    ports: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Progress(Message):
    """Progress payload for long-running commandlets.

    This represents bounded progress as completed work over total work.
    Constructed by: commandlets that report work totals.
    Used by: progress event/display code via `percent`, avoiding repeated
    completion math in callers.
    """

    status: str
    total: int
    completed: int

    @property
    def percent(self) -> int:
        """Return integer completion percentage without dividing by zero."""

        if self.total <= 0:
            # Unknown totals render as 0% rather than raising in UI code.
            return 0
        return int((self.completed / self.total) * 100)
