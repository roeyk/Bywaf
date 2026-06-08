"""Event subscription selector objects.

Provides Subscription, a compact representation of topic filters consumed by the
event store and runner pipeline machinery.

Used by:
- runner and plugins: fetch events matching consumed topics.
- tests: verify pub/sub filtering behavior."""


from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Subscription:
    """A scoped request for events newer than a known high-water mark.

    This represents an event-consumption cursor for topics and runtime scope.
    Constructed by: pipeline and trigger code from commandlet `consumes`
    metadata.
    Used by: the event store to fetch only relevant events and avoid rereads.
    """

    topics: tuple[str, ...]
    # `after_id` is the cursor used by polling pipelines and triggers. It keeps
    # consumers from rereading events they already processed.
    after_id: int = 0
    limit: int = 100
    pipeline_id: str | None = None
    command_run_id: str | None = None
    parent_command_run_id: str | None = None
