"""Read-only runtime row classification helpers."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.stores import EventStoreProtocol

from .classification import is_view_command_line, is_view_commandlet
from .commands import command_run_metadata_by_id, command_run_metadata_by_job_id


def filter_view_run_rows(db: EventStoreProtocol, rows: list[dict]) -> list[dict]:
    """Return command-run rows that represent project-modifying work.

    Called by: `step` listings to hide read-only view commands by default.
    """
    metadata_by_run = command_run_metadata_by_id(db, (str(row["command_run_id"]) for row in rows))
    return [row for row in rows if not is_view_run_row(row, metadata_by_run.get(str(row["command_run_id"]), {}))]


def filter_view_job_rows(db: EventStoreProtocol, rows: list[dict]) -> list[dict]:
    """Return job rows that represent project-modifying work.

    Called by: `job` listings to hide read-only view commands by default.
    """
    metadata_by_job = command_run_metadata_by_job_id(db, (int(row["id"]) for row in rows))
    return [row for row in rows if not is_view_job_row(row, metadata_by_job.get(int(row["id"]), []))]


def is_view_job_row(row: dict, metadata_items: list[dict[str, object]]) -> bool:
    """Return whether a job only ran read-only view commandlets.

    Called by: `filter_view_job_rows()`.
    """
    if metadata_items:
        action_sets = [metadata_database_actions(item) for item in metadata_items]
        if any(actions.intersection({"write", "manage"}) for actions in action_sets):
            return False
        if action_sets and all(actions == {"view"} for actions in action_sets):
            return True
    return is_view_command_line(str(row["command_line"]))


def metadata_database_actions(item: dict[str, object]) -> set[str]:
    """Return normalized database actions from one metadata item.

    Called by: `is_view_job_row()` and tests through the facade.
    """
    actions = item.get("database_actions", [])
    return {str(action) for action in actions} if isinstance(actions, list) else set()


def view_run_ids(db: EventStoreProtocol, rows: Iterable[dict]) -> set[str]:
    """Return command-run ids for rows that are operator views.

    Called by: pipeline and step view filtering.
    """
    row_list = list(rows)
    metadata_by_run = command_run_metadata_by_id(db, (str(row["command_run_id"]) for row in row_list))
    return {
        str(row["command_run_id"])
        for row in row_list
        if is_view_run_row(row, metadata_by_run.get(str(row["command_run_id"]), {}))
    }


def is_view_run_row(row: dict, metadata: dict[str, object]) -> bool:
    """Return whether a runtime row represents a read-only view operation.

    Called by: run/step filtering helpers.
    """
    actions = metadata.get("database_actions")
    if isinstance(actions, list) and actions:
        action_set = {str(action) for action in actions}
        if action_set == {"view"}:
            return True
        if action_set.intersection({"write", "manage"}):
            return False
    args = metadata.get("args")
    return is_view_commandlet(str(row["source"]), args=[str(arg) for arg in args] if isinstance(args, list) else ())
