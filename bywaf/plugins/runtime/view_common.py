"""Shared helpers for runtime view commandlets.

Provides common selector completion and payload-filter row matching for job,
pipeline, and step views.

Used by:
- runtime.job, runtime.pipeline, and runtime.step: keep view selector behavior
  consistent without duplicating DB filtering mechanics."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from bywaf.runtime_display import (
    args_from_command_line,
    commandlet_from_command_line,
    runtime_sort_completion_candidates,
    runtime_view_completion_candidates,
)
from bywaf.stores import EventStoreProtocol

VIEW_COMMANDLETS = {
    "audit",
    "finding_report",
    "job",
    "pipeline",
    "ports",
    "report",
    "result",
    "results",
    "search",
    "step",
}
VIEW_ACTIONS = {
    "artifact": {"list", "search", "show", "verify"},
    "bundle": {"list", "show", "verify"},
    "key": {"list", "show", "test"},
}
MUTATING_ACTIONS = {
    "note": {"add"},
    "report": {"accept", "defer", "reject"},
}


def view_selector_candidates(prefix: str, allowed_sort_keys: Sequence[str]) -> list[str]:
    """Return common runtime-view selector completions."""
    if prefix.startswith("sort="):
        return runtime_sort_completion_candidates(prefix, allowed_sort_keys)
    return runtime_view_completion_candidates(prefix, allowed_sort_keys)


def is_view_command_line(command_line: str) -> bool:
    """Return whether a recorded command line is an operator view command."""
    commandlet = commandlet_from_command_line(command_line)
    args = args_from_command_line(command_line)
    return is_view_commandlet(commandlet, args=args)


def is_view_commandlet(commandlet: str, *, args: Sequence[str] = ()) -> bool:
    """Return whether a commandlet name is a view-style command."""
    name = commandlet.strip()
    short_name = name.rsplit("/", 1)[-1]
    if short_name in MUTATING_ACTIONS:
        return not args or args[0] not in MUTATING_ACTIONS[short_name]
    if short_name in VIEW_ACTIONS:
        return bool(args) and args[0] in VIEW_ACTIONS[short_name]
    return name in VIEW_COMMANDLETS or short_name in VIEW_COMMANDLETS


def command_run_metadata_by_id(db: EventStoreProtocol, run_ids: Iterable[str]) -> dict[str, dict[str, object]]:
    """Return latest recorded commandlet metadata keyed by command-run id."""
    wanted = {str(run_id) for run_id in run_ids if run_id}
    if not wanted:
        return {}
    by_run: dict[str, dict[str, object]] = {}
    for event in db.events_matching(topic="command.run.arguments", limit=100000):
        if not event.command_run_id or event.command_run_id not in wanted:
            continue
        args = event.payload.get("args")
        database_actions = event.payload.get("database_actions")
        by_run[event.command_run_id] = {
            "args": [str(arg) for arg in args] if isinstance(args, list) else [],
            "database_actions": [str(action) for action in database_actions] if isinstance(database_actions, list) else [],
        }
    return by_run


def filter_view_run_rows(db: EventStoreProtocol, rows: list[dict]) -> list[dict]:
    """Return command-run rows that represent project-modifying work."""
    metadata_by_run = command_run_metadata_by_id(db, (str(row["command_run_id"]) for row in rows))
    return [row for row in rows if not is_view_run_row(row, metadata_by_run.get(str(row["command_run_id"]), {}))]


def view_run_ids(db: EventStoreProtocol, rows: Iterable[dict]) -> set[str]:
    """Return command-run ids for rows that are operator views."""
    row_list = list(rows)
    metadata_by_run = command_run_metadata_by_id(db, (str(row["command_run_id"]) for row in row_list))
    return {
        str(row["command_run_id"])
        for row in row_list
        if is_view_run_row(row, metadata_by_run.get(str(row["command_run_id"]), {}))
    }


def is_view_run_row(row: dict, metadata: dict[str, object]) -> bool:
    """Return whether a runtime row represents a read-only view operation."""
    actions = metadata.get("database_actions")
    if isinstance(actions, list) and actions:
        action_set = {str(action) for action in actions}
        if action_set == {"view"}:
            return True
        if action_set.intersection({"write", "manage"}):
            return False
    args = metadata.get("args")
    return is_view_commandlet(str(row["source"]), args=[str(arg) for arg in args] if isinstance(args, list) else ())


def filter_runtime_rows_by_events(db: EventStoreProtocol, kind: str, rows: list[dict], filters: dict[str, str]) -> list[dict]:
    """Return runtime rows that have at least one associated matching event."""
    if not filters:
        return rows
    if kind == "job":
        matched = db.job_ids_matching_payload_filters(filters)
        return [row for row in rows if int(row["id"]) in matched]
    if kind == "pipeline":
        matched = db.pipeline_ids_matching_payload_filters(filters)
        return [row for row in rows if str(row["pipeline_id"]) in matched]
    if kind == "step":
        matched = db.run_ids_matching_payload_filters(filters)
        return [row for row in rows if str(row["command_run_id"]) in matched]
    raise ValueError(f"unknown runtime view kind: {kind}")
