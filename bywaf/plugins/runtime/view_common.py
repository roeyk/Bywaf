"""Shared helpers for runtime view commandlets.

Provides common selector completion and payload-filter row matching for job,
pipeline, and step views.

Used by:
- runtime.job, runtime.pipeline, and runtime.step: keep view selector behavior
  consistent without duplicating DB filtering mechanics."""

from __future__ import annotations

from collections.abc import Sequence

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
