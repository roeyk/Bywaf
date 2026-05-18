"""Event subscription dataclasses shared by store implementations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Subscription:
    """A scoped request for events newer than a known high-water mark."""

    topics: tuple[str, ...]
    after_id: int = 0
    limit: int = 100
    pipeline_id: str | None = None
    command_run_id: str | None = None
    parent_command_run_id: str | None = None

