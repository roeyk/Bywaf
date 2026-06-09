"""Runtime result scope selection and noise filtering.

Used by: `runtime.results.Results.run()` and result follow mode to decide
which event rows should be rendered as operator-facing scan results.
"""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.event.schemas import event_schema
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.job import require_job


# `results` is an operator-facing product view, not a raw audit log. These
# framework/UI topics are still visible through `event`, but they should never
# decide what "the latest scan result" is.
NOISE_TOPIC_PREFIXES = (
    "artifact.",
    "bundle.",
    "command.run.",
    "console.",
    "db.",
    "framework.",
    "job.",
    "key.",
    "note.",
    "plugin.capability.",
    "plugin.progress.",
    "project.",
    "report.",
    "resource.",
    "runtime.",
    "shell.",
    "trigger.",
    "watchdog.",
)
NOISE_TOPICS = {"process.run", "runtime.name.assigned"}

# Results views hide commandlets that already have dedicated runtime views.
# is_result_work_job() checks this set before choosing generic result rendering.
RESULT_VIEW_COMMANDS = {
    "artifact",
    "bundle",
    "event",
    "events",
    "job",
    "pipeline",
    "port",
    "ports",
    "report",
    "result",
    "results",
    "step",
}


def select_result_scope(context: CommandContext, selectors: Namespace) -> Namespace:
    """Return events for an explicit scope or the latest productive step.

    Called by: `Results.run()` and `follow_results()`.
    """
    scope = selectors.scope
    events = context.event_store("results")
    runtime = context.runtime_store("results")
    if scope.get("all") == "true":
        return Namespace(label="all results", scope={"all": "true"}, sort=selectors.sort, events=non_noise_events(events.events_matching(limit=10000)))
    if "job" in scope:
        if scope["job"] == "latest":
            return latest_result_scope(context, sort=selectors.sort)
        row = require_job(context, scope["job"])
        return Namespace(label=f"job={row['id']}", scope={"job": str(row["id"])}, sort=selectors.sort, events=non_noise_events(events.events_for_job(row["id"], limit=10000)))
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return Namespace(
            label=f"pipeline={scope['pipeline']}",
            scope={"pipeline": scope["pipeline"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(pipeline_id=pipeline_id, limit=10000)),
        )
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return Namespace(
            label=f"step={scope['step']}",
            scope={"step": scope["step"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(command_run_id=run_id, limit=10000)),
        )
    return latest_result_scope(context, sort=selectors.sort)


def latest_result_scope(context: CommandContext, *, sort: str = "host") -> Namespace:
    """Return the newest operator work scope.

    Default `results` should follow the last scan-like job the operator ran,
    even when that job is still running or found nothing. Falling back to an
    older productive step would make the command answer a different question
    than "what did the thing I just ran find?"
    """
    events = context.event_store("results latest")
    runtime = context.runtime_store("results latest")
    for row in reversed(runtime.jobs(active_only=False)):
        if context.job_id is not None and str(row["id"]) == str(context.job_id):
            continue
        if not is_result_work_job(str(row["command_line"])):
            continue
        rows = non_noise_events(events.events_for_job(row["id"], limit=10000))
        return Namespace(label=f"latest job={row['id']}", scope={"job": str(row["id"])}, sort=sort, events=rows)
    run_aliases = runtime.run_aliases()
    for row in reversed(runtime.runs(active_only=False)):
        run_id = str(row["command_run_id"])
        rows = non_noise_events(events.events_matching(command_run_id=run_id, limit=10000))
        if rows:
            step_id = run_aliases.get(run_id, run_id)
            return Namespace(label=f"latest step={step_id}", scope={"step": step_id}, sort=sort, events=rows)
    return Namespace(label="latest results", scope={}, sort=sort, events=[])


def is_result_work_job(command_line: str) -> bool:
    """Return whether a job should own the default `results` answer.

    Called by: `latest_result_scope()` while scanning the job history.
    """
    command = command_line.strip().split(maxsplit=1)[0] if command_line.strip() else ""
    command = command.rsplit("/", 1)[-1]
    return command not in RESULT_VIEW_COMMANDS


def result_scope_signature(events: list[Event]) -> tuple[int | None, int]:
    """Return a cheap change detector for a rendered result scope.

    Called by: `follow_results()` to avoid printing unchanged output.
    """
    if not events:
        return (None, 0)
    return (max(event.id or 0 for event in events), len(events))


def non_noise_events(events: list[Event]) -> list[Event]:
    """Filter lifecycle/audit noise out of operator result views."""
    return [event for event in events if not is_noise_topic(event.topic)]


def is_noise_topic(topic: str) -> bool:
    """Return whether a topic is lifecycle/audit noise for result display."""
    if event_schema(topic) is not None:
        return False
    return topic in NOISE_TOPICS or topic.startswith(NOISE_TOPIC_PREFIXES)
