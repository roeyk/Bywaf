"""Runtime event helpers for runner execution.

Provides small framework-owned event publishers and runtime lookup helpers for
variable expansion, notes, runtime names, pipeline existence, and attach cursors.

Used by:
- runner.core: records execution metadata while running commandlets.
- runtime commandlets and tests: rely on stable event topics and payloads.
"""

from __future__ import annotations

from collections.abc import Callable

from ..db import EventStore
from ..event import Event
from ..plugin import CommandContext


def publish_variable_expansion(context: CommandContext, variable_names: tuple[str, ...]) -> Event | None:
    """Record framework-owned `$variable` expansion for this pipeline step."""
    if not variable_names or context._db is None:
        return None
    # Variable expansion happens before commandlet code sees args, so the
    # framework owns both the capability audit and the provenance event.
    context.audit_capability("variable.read")
    return context._db.publish(
        "framework.variable.expanded",
        {
            "operator": "$",
            "variables": list(variable_names),
            "count": len(variable_names),
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "commandlet": context.source,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_note_if_present(db: EventStore, context: CommandContext, note: str | None) -> Event | None:
    """Persist a framework-owned note attached to this pipeline step."""
    if note is None:
        return None
    return db.publish(
        "note.attached",
        {
            "note": note,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
            "parent_command_run_id": context.parent_command_run_id,
            "commandlet": context.source,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_runtime_name(
    db: EventStore,
    target_type: str,
    target_id: str | int,
    display_name: str,
    *,
    job_id: int | None = None,
    pipeline_id: str | None = None,
    command_run_id: str | None = None,
    parent_command_run_id: str | None = None,
) -> Event:
    """Persist a user-assigned runtime name."""
    return db.publish(
        "runtime.name.assigned",
        {
            "target_type": target_type,
            "target_id": str(target_id),
            "name": display_name,
            "job_id": job_id,
            "pipeline_id": pipeline_id,
            "command_run_id": command_run_id,
            "parent_command_run_id": parent_command_run_id,
        },
        "framework",
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        parent_command_run_id=parent_command_run_id,
    )


def pipeline_exists(db: EventStore, pipeline_id: str) -> bool:
    """Return whether the DB knows this pipeline id."""
    return any(row["pipeline_id"] == pipeline_id for row in db.pipelines())


def attach_cursor_event_id(db: EventStore, cursor: str) -> int:
    """Convert an attach `since=` cursor into an event high-water mark."""
    # `beginning` replays historical events into the attached commandlet; `now`
    # makes it a live tail from the current end of the event log.
    cursors: dict[str, Callable[[], int]] = {
        "beginning": lambda: 0,
        "now": db.latest_event_id,
    }
    try:
        return cursors[cursor]()
    except KeyError as exc:
        raise ValueError("since= must be beginning or now") from exc
