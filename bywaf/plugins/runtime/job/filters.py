"""Job row selector helpers.

Provides table-row filtering for the runtime `job` command.

Used by:
- runtime.job: filter historical job listings by status and command text."""

from __future__ import annotations

from bywaf.runtime_display import commandlet_from_command_line

JOB_ROW_FILTER_KEYS = {"status", "commandlet", "command"}


def split_job_row_selectors(tokens: list[str]) -> tuple[list[str], dict[str, str]]:
    """Split job-table selectors from event-payload filters."""
    event_filters: list[str] = []
    row_filters: dict[str, str] = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if key in JOB_ROW_FILTER_KEYS and separator:
            if not value:
                raise ValueError(f"job {key}= requires a value")
            row_filters[key] = value
        else:
            event_filters.append(token)
    return event_filters, row_filters


def filter_job_rows(rows: list[dict], filters: dict[str, str]) -> list[dict]:
    """Return job rows matching job-table selectors."""
    return [row for row in rows if job_row_matches(row, filters)]


def job_row_matches(row: dict, filters: dict[str, str]) -> bool:
    """Return whether one job row matches row-level selectors."""
    for key, expected in filters.items():
        if key == "status" and str(row["status"]) != expected:
            return False
        if key == "commandlet" and commandlet_from_command_line(str(row["command_line"])) != expected:
            return False
        if key == "command" and expected not in str(row["command_line"]):
            return False
    return True
