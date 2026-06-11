"""Event selection helpers for the `ports` result-view commandlet.

Used by: `ports.Ports.run()` and `ports.ports_scope_label()` to resolve
operator selectors into `port.open` events.
"""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.inventory.scope import events_new_to_scope
from bywaf.plugins.runtime.job import require_job


def select_port_events(context: CommandContext, selectors: Namespace) -> list[Event]:
    """Select raw port events from the requested scope.

    With no explicit scope, use the latest portscanner run that actually emitted
    `port.open`. That mirrors how operators consult an nmap result file after a
    scan instead of rereading every previous scan in the project.
    """
    if getattr(selectors, "new", False):
        scoped = select_port_scope_events(context, selectors)
        return events_new_to_scope(context, ("port.open",), scoped, port_event_keys)
    if getattr(selectors, "last", False):
        latest = latest_portscanner_scope(context)
        return latest.events if latest is not None else []
    return select_port_scope_events(context, selectors)


def select_port_scope_events(context: CommandContext, selectors: Namespace) -> list[Event]:
    """Select raw port events from an explicit scope or latest scan."""
    scope = selectors.scope
    events = context.event_store("ports")
    runtime = context.runtime_store("ports")
    if scope.get("all") == "true":
        return events.events_matching(topic="port.open", limit=10000)
    if "job" in scope:
        if scope["job"] == "latest":
            latest = latest_portscanner_scope(context)
            return latest.events if latest is not None else []
        row = require_job(context, scope["job"])
        return events.events_for_job_topic(row["id"], "port.open", limit=10000)
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return events.events_matching(topic="port.open", pipeline_id=pipeline_id, limit=10000)
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return events.events_matching(topic="port.open", command_run_id=run_id, limit=10000)
    latest = latest_portscanner_scope(context)
    return latest.events if latest is not None else []


def port_event_keys(event: Event) -> set[tuple[str, int, str]]:
    """Return the stable open-port fact identity."""
    payload = event.payload
    return {(str(payload.get("host") or ""), int(payload.get("port") or 0), str(payload.get("protocol") or "tcp"))}


def latest_portscanner_scope(context: CommandContext) -> Namespace | None:
    """Return the newest productive portscanner scope."""
    store = context.event_store("ports latest")
    runtime = context.runtime_store("ports latest")
    for event in reversed(store.events_matching(topic="port.open", limit=10000)):
        if not event.command_run_id:
            continue
        jobs = runtime.jobs_for_run(event.command_run_id)
        if jobs and not any(command_is_portscanner(str(row["command_line"])) for row in jobs):
            continue
        scoped_events = store.events_matching(topic="port.open", command_run_id=event.command_run_id, limit=10000)
        if scoped_events:
            job_id = str(jobs[-1]["id"]) if jobs else ""
            return Namespace(command_run_id=event.command_run_id, job_id=job_id, events=scoped_events)
    return None


def command_is_portscanner(command_line: str) -> bool:
    """Return whether a stored command line targets the portscanner commandlet."""
    first = command_line.split(maxsplit=1)[0] if command_line.split() else ""
    return first in {"portscanner", "network/portscanner"}


__all__ = [
    "command_is_portscanner",
    "latest_portscanner_scope",
    "port_event_keys",
    "select_port_events",
    "select_port_scope_events",
]
