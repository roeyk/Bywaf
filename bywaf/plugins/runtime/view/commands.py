"""Recorded command metadata lookup helpers for runtime views.

Used by:
- runtime commandlets and REPL display paths that present persisted jobs,
  events, inventory, or result state.
- tests and future plugins that need stable runtime helper behavior.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.stores import EventStoreProtocol


def run_meta_by_id(db: EventStoreProtocol, run_ids: Iterable[str]) -> dict[str, dict[str, object]]:
    """Return latest recorded commandlet metadata keyed by command-run id.

    Called by: step/pipeline view row classifiers.
    """
    wanted = {str(run_id) for run_id in run_ids if run_id}
    if not wanted:
        return {}
    by_run: dict[str, dict[str, object]] = {}
    for event in db.events_matching(topic="command.run.arguments", limit=100000):
        if not event.command_run_id or event.command_run_id not in wanted:
            continue
        by_run[event.command_run_id] = _metadata_from_payload(event.payload)
    return by_run


def run_meta_by_job(db: EventStoreProtocol, job_ids: Iterable[int]) -> dict[int, list[dict[str, object]]]:
    """Return recorded commandlet metadata grouped by job id.

    Called by: job view row classifiers.
    """
    wanted = {int(job_id) for job_id in job_ids}
    if not wanted:
        return {}
    by_job: dict[int, list[dict[str, object]]] = {}
    for event in db.events_matching(topic="command.run.arguments", limit=100000):
        job_id = event.payload.get("job_id")
        if not isinstance(job_id, int) or job_id not in wanted:
            continue
        by_job.setdefault(job_id, []).append(_metadata_from_payload(event.payload))
    return by_job


def _metadata_from_payload(payload: dict[str, object]) -> dict[str, object]:
    """Return normalized command metadata from one `command.run.arguments` event."""
    args = payload.get("args")
    database_actions = payload.get("database_actions")
    return {
        "args": [str(arg) for arg in args] if isinstance(args, list) else [],
        "database_actions": [str(action) for action in database_actions] if isinstance(database_actions, list) else [],
    }
