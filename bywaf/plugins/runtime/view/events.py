"""Event-payload filtering helpers for runtime list views.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from collections.abc import Callable

from bywaf.stores import EventStoreProtocol

RuntimeEventMatcher = Callable[[EventStoreProtocol, dict[str, str]], set[int] | set[str]]

# Dispatch table used by `filter_rows_by_events()` to replace a
# kind-specific `if`/`elif` ladder for payload-filter lookups.
EVENT_MATCHERS: dict[str, RuntimeEventMatcher] = {
    "job": lambda db, filters: db.job_ids_for_filters(filters),
    "pipeline": lambda db, filters: db.pipeline_ids_for_filters(filters),
    "step": lambda db, filters: db.run_ids_for_filters(filters),
}


def filter_rows_by_events(db: EventStoreProtocol, kind: str, rows: list[dict], filters: dict[str, str]) -> list[dict]:
    """Return runtime rows that have at least one associated matching event."""
    if not filters:
        return rows
    try:
        matched = EVENT_MATCHERS[kind](db, filters)
    except KeyError:
        raise ValueError(f"unknown runtime view kind: {kind}") from None
    if kind == "job":
        return [row for row in rows if int(row["id"]) in matched]
    if kind == "pipeline":
        return [row for row in rows if str(row["pipeline_id"]) in matched]
    if kind == "step":
        return [row for row in rows if str(row["command_run_id"]) in matched]
    raise ValueError(f"unknown runtime view kind: {kind}")
