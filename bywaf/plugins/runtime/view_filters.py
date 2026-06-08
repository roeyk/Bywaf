"""Filter runtime view rows by selectors, cursor state, and event metadata."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.operator_state import update_view_cursor, view_cursor
from bywaf.stores import EventStoreProtocol

from .view_classification import is_view_command_line, is_view_commandlet


def filter_runtime_rows_since(runtime, kind: str, rows: list[dict], since: str) -> list[dict]:
    """Return runtime rows newer than a local runtime id or durable serial."""
    if not since:
        return rows
    if kind == "job":
        threshold = resolve_job_since(runtime, since)
        return [row for row in rows if int(row["id"]) > threshold]
    if kind == "pipeline":
        aliases = runtime.pipeline_aliases()
        threshold = resolve_alias_since("pipeline", aliases, runtime.resolve_pipeline_serial(since), since)
        return [row for row in rows if int(aliases.get(str(row["pipeline_id"]), "0")) > threshold]
    if kind == "step":
        aliases = runtime.run_aliases()
        threshold = resolve_alias_since("step", aliases, runtime.resolve_run_serial(since), since)
        return [row for row in rows if int(aliases.get(str(row["command_run_id"]), "0")) > threshold]
    raise ValueError(f"unknown runtime view kind: {kind}")


def apply_runtime_new_cursor(context, kind: str, rows: list[dict], enabled: bool) -> tuple[list[dict], int]:
    """Filter rows to those newer than a local view cursor and advance it.

    The cursor is operator-local JSON state, not a database event. The returned
    integer is the newest local row ID so callers can highlight it.
    """
    newest = newest_runtime_row_id(context.runtime_store(f"{kind} new cursor"), kind, rows)
    if not enabled:
        return rows, 0
    runner = context.metadata.get("runner")
    threshold = view_cursor(runner, kind)
    new_rows = [row for row in rows if runtime_row_local_id(context.runtime_store(f"{kind} new cursor"), kind, row) > threshold]
    if newest:
        update_view_cursor(runner, kind, newest)
    return new_rows, newest_runtime_row_id(context.runtime_store(f"{kind} new cursor"), kind, new_rows)


def newest_runtime_row_id(runtime, kind: str, rows: list[dict]) -> int:
    """Return the newest local runtime ID in a row set."""
    return max((runtime_row_local_id(runtime, kind, row) for row in rows), default=0)


def runtime_row_local_id(runtime, kind: str, row: dict) -> int:
    """Return one row's local runtime selector as an integer."""
    if kind == "job":
        return int(row["id"])
    if kind == "pipeline":
        return int(runtime.pipeline_aliases().get(str(row["pipeline_id"]), "0"))
    if kind == "step":
        return int(runtime.run_aliases().get(str(row["command_run_id"]), "0"))
    raise ValueError(f"unknown runtime view kind: {kind}")


def resolve_job_since(runtime, since: str) -> int:
    """Resolve a job `since=` selector to a local numeric job id."""
    if since.isdigit():
        return int(since)
    resolved = runtime.job_id_for_serial(since)
    if resolved is None:
        raise ValueError(f"unknown job since= selector: {since}")
    return int(resolved)


def resolve_alias_since(kind: str, aliases: dict[str, str], serial: str, raw: str) -> int:
    """Resolve a step/pipeline `since=` selector to a local numeric alias."""
    if raw.isdigit():
        return int(raw)
    alias = aliases.get(serial)
    if alias is None:
        raise ValueError(f"unknown {kind} since= selector: {raw}")
    return int(alias)


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


def filter_view_job_rows(db: EventStoreProtocol, rows: list[dict]) -> list[dict]:
    """Return job rows that represent project-modifying work."""
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
