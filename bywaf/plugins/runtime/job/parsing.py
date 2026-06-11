"""Parsing and validation helpers for the runtime `job` command."""

from __future__ import annotations

from argparse import Namespace

from bywaf.plugins.runtime.job.filters import split_job_row_selectors
from bywaf.plugins.runtime.view_common import split_since_selector, view_selector_candidates
from bywaf.runtime_display import parse_runtime_list_selectors

JOB_ACTIONS = ("cancel", "end", "kill")
REMOVED_JOB_ACTIONS = {"list", "show"}
JOB_SORT_KEYS = ("id", "serial", "state", "status", "started", "commandlet")


def parse_job_operation(tokens: list[str]) -> Namespace:
    """Interpret terse `job` forms into the internal action/id/filter shape.

    Called by: `Job.run()` and `Job.database_actions_for_args()`.
    """
    if not tokens:
        return Namespace(action="list", id=None, filters={}, row_filters={}, since="", sort="")
    first, rest = tokens[0], tokens[1:]
    if first in REMOVED_JOB_ACTIONS:
        raise ValueError("usage: job [--all] [field=value ...] | job <id> | job <cancel|end|kill> [options] <id>")
    if first in JOB_ACTIONS:
        if not rest:
            raise ValueError(f"job {first} requires a job id")
        selectors, since = split_since_selector("job", rest[1:])
        filters, sort = parse_runtime_list_selectors(selectors, allowed_sort_keys=JOB_SORT_KEYS, command="job")
        return Namespace(action=first, id=rest[0], filters=filters, row_filters={}, since=since, sort=sort)
    if first.startswith("serial=") and not rest:
        return Namespace(action="show", id=first.split("=", 1)[1], filters={}, row_filters={}, since="", sort="")
    if "=" not in first and not rest:
        return Namespace(action="show", id=first, filters={}, row_filters={}, since="", sort="")
    selectors, since = split_since_selector("job", tokens)
    selectors, row_filters = split_job_row_selectors(selectors)
    filters, sort = parse_runtime_list_selectors(selectors, allowed_sort_keys=JOB_SORT_KEYS, command="job")
    return Namespace(action="list", id=None, filters=filters, row_filters=row_filters, since=since, sort=sort)


def validate_job_mode(action: str, *, soft: bool, hard: bool) -> None:
    """Reject ambiguous mode flags for job management operations.

    Called by: `Job.run()` after argument parsing and before dispatch.
    """
    if soft and hard:
        raise ValueError("--soft cannot be combined with --hard")
    if action == "cancel" and (soft or hard):
        raise ValueError("job cancel is already cooperative; use job end --hard or job kill --hard for forced termination")
    if action not in {"end", "kill"} and (soft or hard):
        raise ValueError(f"job {action} does not accept --soft or --hard")


def job_completion_candidates(args: list[str], prefix: str, job_ids: list[str]) -> list[str]:
    """Return completion candidates for the `job` command.

    Called by: `Job.complete()`.
    """
    root_candidates = ["--all", "--new", "--page", "sort=", "since=", "status=", "commandlet=", "command=", *job_ids, *JOB_ACTIONS]
    if not args:
        return root_candidates
    if len(args) == 1 and args[0] in JOB_ACTIONS:
        return job_ids
    if args and args[-1].startswith("sort="):
        return view_selector_candidates(args[-1], JOB_SORT_KEYS)
    if len(args) == 1:
        candidates = [*root_candidates, *view_selector_candidates(prefix, JOB_SORT_KEYS)]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]
    if len(args) >= 2 and args[0] in JOB_ACTIONS:
        return job_ids
    return []
