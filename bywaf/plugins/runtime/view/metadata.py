"""Facade for runtime read-only command metadata filtering.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from .commands import run_meta_by_id, run_meta_by_job
from .rows import (
    filter_view_job_rows,
    filter_view_run_rows,
    is_view_job_row,
    is_view_run_row,
    metadata_database_actions,
    view_run_ids,
)

__all__ = [
    "run_meta_by_id",
    "run_meta_by_job",
    "filter_view_job_rows",
    "filter_view_run_rows",
    "is_view_job_row",
    "is_view_run_row",
    "metadata_database_actions",
    "view_run_ids",
]
