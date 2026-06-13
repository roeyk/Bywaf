"""Follow-mode polling for REPL event commands.

Used by:
- interactive REPL commands, app-dispatch helpers, and display tests.
- operators who inspect runtime state through built-in commands.
"""

from __future__ import annotations

import time

from ....event.filters import select_event_rows
from ....runner import Runner
from ...display import print_events
from .parsing import EventFollowQuery


def follow_events(runner: Runner, query: EventFollowQuery) -> None:
    """Stream event-ledger rows until Ctrl-C or a one-shot follow completes.

    Called by: `events.handle_event_command()` for `event follow ...`.
    """
    pipeline_id, command_run_id = resolve_event_follow_scope(runner, query)
    job_id = resolve_job_selector(runner, str(query.scope_value)) if query.scope_key == "job" else None
    after_id = 0 if query.since == "beginning" else runner.events.latest_event_id()
    print("following events; press Ctrl-C to stop")
    try:
        while True:
            events = followed_event_batch(runner, query, after_id, job_id, pipeline_id, command_run_id)
            if events:
                after_id = max(event.id or after_id for event in events)
                print_events(select_event_rows(events, query.filters, "time", query.limit), runner)
                if query.once:
                    return
            elif query.once:
                return
            else:
                time.sleep(query.interval)
    except KeyboardInterrupt:
        print("stopped following events")


def followed_event_batch(
    runner: Runner,
    query: EventFollowQuery,
    after_id: int,
    job_id: int | None,
    pipeline_id: str | None,
    command_run_id: str | None,
):
    """Return the next event batch for one follow scope."""
    source_limit = max(query.limit * 20, 100)
    if job_id is not None and query.topic is not None:
        return runner.events.events_for_job_topic(
            job_id,
            query.topic,
            after_id=after_id,
            limit=source_limit,
        )
    if job_id is not None:
        return runner.events.events_for_job(job_id, after_id=after_id, limit=source_limit)
    return runner.events.events_after(
        after_id,
        topic=query.topic,
        pipeline_id=pipeline_id,
        command_run_id=command_run_id,
        limit=source_limit,
    )


def resolve_event_follow_scope(runner: Runner, query: EventFollowQuery) -> tuple[str | None, str | None]:
    """Resolve follow selectors to durable pipeline and step serials."""
    if query.scope_key == "job":
        return None, None
    if query.scope_key == "pipeline":
        return runner.runtime.resolve_pipeline_serial(str(query.scope_value)), None
    if query.scope_key == "step":
        return None, runner.runtime.resolve_run_serial(str(query.scope_value))
    return None, None


def resolve_job_selector(runner: Runner, value: str) -> int:
    """Resolve a local job id or durable job serial for built-in selectors."""
    try:
        return int(value)
    except ValueError:
        resolved = runner.runtime.job_id_for_serial(value)
        if resolved is None:
            raise ValueError(f"unknown job: {value}") from None
        return int(resolved)
