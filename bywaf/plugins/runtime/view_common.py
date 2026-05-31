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


def split_since_selector(command: str, tokens: Sequence[str]) -> tuple[list[str], str]:
    """Remove one `since=` runtime selector from a token list.

    Runtime IDs are local operator selectors, so `job since=120` means jobs
    after local job 120, `pipeline since=30` means pipelines after local
    pipeline 30, and `step since=90` means steps after local step 90.
    """
    selectors: list[str] = []
    since = ""
    for token in tokens:
        key, separator, value = token.partition("=")
        if key == "since" and separator:
            if since:
                raise ValueError(f"{command} accepts only one since= selector")
            if not value:
                raise ValueError(f"{command} since= requires an id")
            since = value
        else:
            selectors.append(token)
    return selectors, since


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
