"""Read-only metadata filtering helpers for runtime list views."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.stores import EventStoreProtocol

from .view_classification import is_view_command_line, is_view_commandlet


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


def command_run_metadata_by_job_id(db: EventStoreProtocol, job_ids: Iterable[int]) -> dict[int, list[dict[str, object]]]:
    """Return recorded commandlet metadata grouped by job id."""
    wanted = {int(job_id) for job_id in job_ids}
    if not wanted:
        return {}
    by_job: dict[int, list[dict[str, object]]] = {}
    for event in db.events_matching(topic="command.run.arguments", limit=100000):
        job_id = event.payload.get("job_id")
        if not isinstance(job_id, int) or job_id not in wanted:
            continue
        args = event.payload.get("args")
        database_actions = event.payload.get("database_actions")
        by_job.setdefault(job_id, []).append(
            {
                "args": [str(arg) for arg in args] if isinstance(args, list) else [],
                "database_actions": [str(action) for action in database_actions] if isinstance(database_actions, list) else [],
            }
        )
    return by_job


def is_view_job_row(row: dict, metadata_items: list[dict[str, object]]) -> bool:
    """Return whether a job only ran read-only view commandlets."""
    if metadata_items:
        action_sets = [metadata_database_actions(item) for item in metadata_items]
        if any(actions.intersection({"write", "manage"}) for actions in action_sets):
            return False
        if action_sets and all(actions == {"view"} for actions in action_sets):
            return True
    return is_view_command_line(str(row["command_line"]))


def metadata_database_actions(item: dict[str, object]) -> set[str]:
    """Return normalized database actions from one metadata item."""
    actions = item.get("database_actions", [])
    return {str(action) for action in actions} if isinstance(actions, list) else set()


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
