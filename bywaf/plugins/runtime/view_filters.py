"""Compatibility facade for runtime view row filters.

Runtime filtering helpers are grouped by responsibility in sibling modules:

- `view_cursor_filters`: local cursors, `--new`, and `since=`.
- `view_metadata_filters`: read-only command metadata classification.
- `view_event_filters`: event-payload selector filtering.

This module keeps the original import surface stable for job, pipeline, and
step commandlets.
"""

from __future__ import annotations

from .view_cursor_filters import (
    apply_runtime_new_cursor,
    filter_runtime_rows_since,
    newest_runtime_row_id,
    resolve_alias_since,
    resolve_job_since,
    runtime_row_local_id,
)
from .view_event_filters import EVENT_MATCHERS, filter_runtime_rows_by_events
from .view_metadata_filters import (
    command_run_metadata_by_id,
    command_run_metadata_by_job_id,
    filter_view_job_rows,
    filter_view_run_rows,
    is_view_job_row,
    is_view_run_row,
    metadata_database_actions,
    view_run_ids,
)

__all__ = [
    "EVENT_MATCHERS",
    "apply_runtime_new_cursor",
    "command_run_metadata_by_id",
    "command_run_metadata_by_job_id",
    "filter_runtime_rows_by_events",
    "filter_runtime_rows_since",
    "filter_view_job_rows",
    "filter_view_run_rows",
    "is_view_job_row",
    "is_view_run_row",
    "metadata_database_actions",
    "newest_runtime_row_id",
    "resolve_alias_since",
    "resolve_job_since",
    "runtime_row_local_id",
    "view_run_ids",
]
