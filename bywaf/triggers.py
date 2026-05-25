"""Trigger evaluation and service orchestration.

Provides trigger cursor handling, event matching, action dispatch, loop guards,
and session service lifecycle helpers for provider-owned trigger rules.

Used by:
- REPL shell and runner startup: start/stop trigger services for a session.
- registry-provided trigger specs: evaluate event-driven actions."""


from __future__ import annotations

import os
import shlex
import signal
import time

from .events import Event
from .runner import Runner
from .specs import TriggerSpec


def start_default_services(runner: Runner) -> None:
    """Run framework trigger providers for session-scoped services."""
    for trigger in runner.registry.triggers:
        enable_session_trigger(runner, trigger)
        if framework_trigger_fired(runner, trigger):
            start_trigger_action(runner, trigger)


def framework_trigger_fired(runner: Runner, trigger: TriggerSpec) -> bool:
    """Return whether a provider-owned trigger has matched new event history.

    Trigger services poll the event log.  Each trigger keeps a durable cursor in
    the database and an in-memory cursor for the current session, so restarts do
    not replay old events while a single shell session also avoids duplicate
    firings before the durable state is flushed.
    """
    trigger_id = runner.registry.trigger_id(trigger)
    after_id = runner.trigger_event_cursors.get(trigger_id, runner.db.trigger_cursor(trigger_id))
    latest_seen = after_id
    fired = False

    # Walk only event rows newer than the trigger cursor.  `latest_seen` moves
    # forward even when an event does not match, so future checks do not keep
    # rescanning irrelevant history.
    for event in runner.db.events_matching(topic=trigger.topic, after_id=after_id, limit=10000):
        event_id = int(event.id or 0)
        latest_seen = max(latest_seen, event_id)

        # The durable cursor protects across process restarts.  This in-memory
        # set protects within one interactive session if this function is called
        # repeatedly before the trigger state is persisted or observed by every
        # service loop.
        fire_key = (trigger_id, event_id)
        if fire_key in runner.fired_session_trigger_events:
            continue
        if not trigger_matches(runner, trigger, event):
            continue
        runner.fired_session_trigger_events.add(fire_key)

        # Publish an audit event before starting the action.  The payload keeps
        # both trigger metadata and the concrete source event that caused this
        # firing, which is what later audit/report tooling needs to explain why
        # a background service or action was launched.
        payload = trigger_payload(runner, trigger)
        payload.update(
            {
                "trigger_event_id": event_id,
                "trigger_event_topic": event.topic,
                "trigger_event_source": event.source,
            }
        )
        runner.db.publish("framework.trigger.fired", payload, "framework")
        runner.db.update_trigger_state(
            trigger_id,
            enabled=True,
            last_event_id=event_id,
            last_fired_event_id=event_id,
        )
        fired = True

        # Fire at most once per polling pass.  Service loops call this again
        # after the action has been started, which prevents a large backlog from
        # launching many copies of the same trigger action at once.
        break

    # Persist the cursor whether or not a trigger fired.  Otherwise a non-match
    # would be rechecked forever, and service triggers watching high-volume
    # topics could spend most of their time rereading old rows.
    runner.trigger_event_cursors[trigger_id] = latest_seen
    runner.db.update_trigger_state(trigger_id, enabled=True, last_event_id=latest_seen)
    return fired


def start_trigger_action(runner: Runner, trigger: TriggerSpec) -> None:
    """Start or run a trigger action command according to its mode."""
    if trigger.action_mode not in {"service", "background", "foreground"}:
        raise ValueError(f"unknown trigger action mode: {trigger.action_mode}")
    if trigger.action_mode == "foreground":
        runner.execute(trigger.action_command)
        return
    if trigger.action_mode == "service" and any(
        str(row["command_line"] or "") == trigger.action_command
        for row in runner.db.jobs(active_only=True)
    ):
        return
    event = runner.start_background(trigger.action_command)
    if trigger.action_mode == "service":
        job_id = event.payload.get("job_id")
        if isinstance(job_id, int):
            runner.session_service_job_ids.add(job_id)


def trigger_matches(runner: Runner, trigger: TriggerSpec, event: Event) -> bool:
    """Return whether one event satisfies a provider-owned trigger spec."""
    if trigger.capability is not None and event.payload.get("capability") != trigger.capability:
        return False
    for key, expected in trigger.payload_equals:
        if str(event.payload.get(key, "")) != expected:
            return False
    if event.payload.get("commandlet") in trigger.exclude_commandlets:
        return False
    if trigger.suppress_self_trigger and event.source == trigger_action_name(trigger):
        return False
    if not trigger.active_job:
        return True
    job_id = event.payload.get("job_id")
    if not isinstance(job_id, int):
        return False
    active_job_ids = {int(row["id"]) for row in runner.db.jobs(active_only=True)}
    return job_id in active_job_ids


def enable_session_trigger(runner: Runner, trigger: TriggerSpec) -> None:
    """Audit that a provider-owned trigger is active for this session."""
    trigger_id = runner.registry.trigger_id(trigger)
    if trigger_id in runner.enabled_session_triggers:
        return
    runner.enabled_session_triggers.add(trigger_id)
    cursor = runner.db.trigger_cursor(trigger_id)
    if cursor:
        runner.trigger_event_cursors.setdefault(trigger_id, cursor)
    runner.db.update_trigger_state(trigger_id, enabled=True, last_event_id=cursor)
    runner.db.publish("framework.trigger.enabled", trigger_payload(runner, trigger), "framework")


def disable_session_triggers(runner: Runner) -> None:
    """Audit provider-owned trigger deactivation for this session."""
    if not runner.enabled_session_triggers:
        return
    triggers_by_id = {runner.registry.trigger_id(trigger): trigger for trigger in runner.registry.triggers}
    for trigger_id in sorted(runner.enabled_session_triggers):
        trigger = triggers_by_id.get(trigger_id)
        payload = trigger_payload(runner, trigger) if trigger is not None else {"trigger_id": trigger_id}
        runner.db.update_trigger_state(trigger_id, enabled=False)
        runner.db.publish("framework.trigger.disabled", payload, "framework")
    runner.enabled_session_triggers.clear()


def trigger_payload(runner: Runner, trigger: TriggerSpec) -> dict[str, object]:
    """Return audit payload metadata for one provider-owned trigger."""
    payload: dict[str, object] = {
        "trigger_id": runner.registry.trigger_id(trigger),
        "name": trigger.name,
        "topic": trigger.topic,
        "action_command": trigger.action_command,
        "action_mode": trigger.action_mode,
        "description": trigger.description,
        "active_job": trigger.active_job,
        "payload_equals": dict(trigger.payload_equals),
        "exclude_commandlets": list(trigger.exclude_commandlets),
        "suppress_self_trigger": trigger.suppress_self_trigger,
    }
    provider = runner.registry.trigger_provider(trigger)
    if provider is not None:
        payload["provider"] = provider
    if trigger.capability is not None:
        payload["capability"] = trigger.capability
    return payload


def trigger_action_name(trigger: TriggerSpec) -> str:
    """Return the commandlet name invoked by a trigger action."""
    return shlex.split(trigger.action_command)[0] if trigger.action_command.strip() else ""


def stop_session_services(runner: Runner) -> None:
    """Stop default session-scoped services started by the interactive shell.

    Session services are background jobs launched automatically by framework
    triggers, such as watchdog-style helpers.  On shell shutdown we request a
    cooperative cancellation first, wait briefly for the child process to exit,
    and then force-kill only the jobs that ignore the graceful stop.
    """
    if not runner.session_service_job_ids:
        return

    # Only stop jobs that this session started as services.  Other active jobs
    # may be user-launched scans and should survive ordinary trigger cleanup.
    for row in runner.db.jobs(active_only=True):
        if int(row["id"]) not in runner.session_service_job_ids:
            continue
        job_id = int(row["id"])

        # Record the cancellation request in the runtime store before touching
        # the OS process.  Cooperative commandlets can observe this request and
        # exit cleanly, and audit output can explain why the job stopped.
        runner.db.request_cancellation("job", str(job_id), reason="session shutdown")
        runner.db.update_job_status(job_id, "cancelling")
        pid = row["pid"]
        if pid is None:
            continue

        # Give cooperative services a short grace window.  The shell is already
        # exiting at this point, so this needs to be long enough for cleanup but
        # short enough not to make shutdown feel hung.
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if not process_exists(int(pid)):
                runner.db.finish_job(job_id, "cancelled")
                break
            time.sleep(0.05)
        else:
            # If the service ignores cancellation, force termination and record
            # that distinction.  A missing process is harmless because it may
            # have exited between the final poll and the kill call.
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            runner.db.finish_job(job_id, "killed")


def process_exists(pid: int) -> bool:
    """Return whether a process id still exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
