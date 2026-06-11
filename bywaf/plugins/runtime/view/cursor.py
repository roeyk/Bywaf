"""Cursor and `since=` filtering helpers for runtime list views."""

from __future__ import annotations

from bywaf.operator_state import update_view_cursor, view_cursor


def filter_runtime_rows_since(runtime, kind: str, rows: list[dict], since: str) -> list[dict]:
    """Return runtime rows newer than a local runtime id or durable serial.

    Called by: job, pipeline, and step list renderers after base rows are read
    and before event-payload filters are applied.
    """
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
