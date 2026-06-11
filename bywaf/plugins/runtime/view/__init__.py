"""Shared facade for runtime view commandlets.

The runtime view helpers are grouped by responsibility in package modules:

- `classification`: recognizes read-only operator view commands.
- `filters`: applies cursor, `since=`, metadata, and event filters.

Used by: job, pipeline, and step commandlets for shared selector parsing,
view filtering, and completion candidates.
"""

from __future__ import annotations

from collections.abc import Sequence

from bywaf.runtime_display import runtime_sort_completion_candidates, runtime_view_completion_candidates

from .classification import (
    MUTATING_ACTIONS as MUTATING_ACTIONS,
    VIEW_ACTIONS as VIEW_ACTIONS,
    VIEW_COMMANDLETS as VIEW_COMMANDLETS,
    is_view_command_line as is_view_command_line,
    is_view_commandlet as is_view_commandlet,
)
from .filters import (
    apply_runtime_new_cursor as apply_runtime_new_cursor,
    command_run_metadata_by_id as command_run_metadata_by_id,
    command_run_metadata_by_job_id as command_run_metadata_by_job_id,
    filter_runtime_rows_by_events as filter_runtime_rows_by_events,
    filter_runtime_rows_since as filter_runtime_rows_since,
    filter_view_job_rows as filter_view_job_rows,
    filter_view_run_rows as filter_view_run_rows,
    is_view_job_row as is_view_job_row,
    is_view_run_row as is_view_run_row,
    metadata_database_actions as metadata_database_actions,
    newest_runtime_row_id as newest_runtime_row_id,
    resolve_alias_since as resolve_alias_since,
    resolve_job_since as resolve_job_since,
    runtime_row_local_id as runtime_row_local_id,
    view_run_ids as view_run_ids,
)


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
