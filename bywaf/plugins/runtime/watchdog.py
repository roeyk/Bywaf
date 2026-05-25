"""Runtime watchdog commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Controls and inspects watchdog behavior for long-running operations.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import argparse
from argparse import Namespace
from collections.abc import Iterable
from datetime import datetime, timezone
import time
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, TriggerSpec, commandlet, option
from bywaf.plugins._args import key_value_to_long_options

ACTIVE_STATUSES = {"queued", "claimed", "running", "pausing", "paused", "cancelling"}
ERROR_TOPICS = {"command.run.failed", "job.failed", "tool.error"}
OPTION_KEYS = {"error-threshold", "interval", "stall-threshold", "timeout"}


def triggers() -> tuple[TriggerSpec, ...]:
    """Return provider-owned trigger rules for the watchdog service."""
    return (
        TriggerSpec(
            name="network-access-starts-watchdog",
            topic="plugin.capability.used",
            action_command="watchdog --session-service",
            description="ON network.connect capability use by an active job DO start the session watchdog",
            action_mode="service",
            capability="network.connect",
            active_job=True,
            exclude_commandlets=("watchdog",),
        ),
    )


@commandlet(
    name="watchdog",
    description="Monitor active jobs for stalls, timeouts, and repeated errors.",
    usage="watchdog [--once] [interval=seconds] [timeout=seconds] [stall-threshold=seconds] [error-threshold=count]",
    examples=(
        "watchdog --once",
        "watchdog interval=10 timeout=300 stall-threshold=120 error-threshold=10 &",
    ),
    emits=("watchdog.timeout", "watchdog.stalled", "watchdog.error_rate"),
    capabilities=(
        "db.read:*",
        "db.write:watchdog.timeout",
        "db.write:watchdog.stalled",
        "db.write:watchdog.error_rate",
        "framework.console.alert",
    ),
)
@option("error-threshold", "number of error events before warning", "10")
@option("interval", "seconds between service checks", "5")
@option("stall-threshold", "seconds without job events before warning", "120")
@option("timeout", "seconds a job may run before warning", "300")
@option("silent", "suppress console alerts", "false")
class Watchdog(CommandletBase):
    """Long-running service commandlet that observes runtime health."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run one watchdog pass or loop until cancelled."""
        del input_events
        parser = self.parser()
        parser.add_argument("--error-threshold", type=int, default=self.var_default(context, "error-threshold", 10, cast=int))
        parser.add_argument("--interval", type=float, default=self.var_default(context, "interval", 5.0, cast=float))
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--session-service", action="store_true", help=argparse.SUPPRESS)
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--stall-threshold", type=float, default=self.var_default(context, "stall-threshold", 120.0, cast=float))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 300.0, cast=float))
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))
        validate_thresholds(parsed)
        emitted: set[tuple[str, int]] = set()
        while True:
            # Long-running mode keeps state in memory only to suppress repeated
            # alerts during this invocation; durable evidence is the events.
            check_active_jobs(context, parsed, emitted)
            if parsed.once or context.cancelled():
                return ()
            time.sleep(parsed.interval)


def validate_thresholds(parsed: Namespace) -> None:
    """Reject nonsensical watchdog thresholds before entering the service loop."""
    if parsed.error_threshold < 1:
        raise ValueError("error-threshold must be at least 1")
    if parsed.interval <= 0:
        raise ValueError("interval must be greater than 0")
    if parsed.stall_threshold <= 0:
        raise ValueError("stall-threshold must be greater than 0")
    if parsed.timeout <= 0:
        raise ValueError("timeout must be greater than 0")


def check_active_jobs(context: CommandContext, parsed: Namespace, emitted: set[tuple[str, int]]) -> None:
    """Inspect active jobs and emit each warning type once per job."""
    runtime = context.runtime_store("watchdog")
    context.audit_capability("db.read:*")
    now = datetime.now(timezone.utc)
    for row in runtime.jobs(active_only=True):
        if str(row["command_line"] or "").startswith("watchdog"):
            # Avoid recursive watchdog-on-watchdog alerts when the trigger
            # starts the watchdog as a session service.
            continue
        job = job_snapshot(context, row)
        if job.status not in ACTIVE_STATUSES:
            continue
        age = seconds_since(job.started_at, now)
        if age is not None and age >= parsed.timeout:
            emit_once(context, parsed, emitted, "watchdog.timeout", job, observed=age, threshold=parsed.timeout)
        idle = seconds_since(job.last_event_at, now)
        if idle is not None and idle >= parsed.stall_threshold:
            emit_once(context, parsed, emitted, "watchdog.stalled", job, observed=idle, threshold=parsed.stall_threshold)
        if job.error_events >= parsed.error_threshold:
            emit_once(
                context,
                parsed,
                emitted,
                "watchdog.error_rate",
                job,
                observed=job.error_events,
                threshold=parsed.error_threshold,
            )


class JobSnapshot:
    """Small runtime view of one active job."""

    def __init__(
        self,
        *,
        job_id: int,
        serial: str,
        command_line: str,
        status: str,
        started_at: datetime | None,
        last_event_at: datetime | None,
        last_event_id: int | None,
        error_events: int,
    ) -> None:
        self.job_id = job_id
        self.serial = serial
        self.command_line = command_line
        self.status = status
        self.started_at = started_at
        self.last_event_at = last_event_at
        self.last_event_id = last_event_id
        self.error_events = error_events


def job_snapshot(context: CommandContext, row: Any) -> JobSnapshot:
    """Build a watchdog-friendly snapshot from a runtime job row."""
    job_id = int(row["id"])
    # The job row has coarse lifecycle state; event history tells us whether
    # work is still producing output and whether errors are accumulating.
    events = context.event_store("watchdog").events_for_job(job_id, limit=10000)
    last = events[-1] if events else None
    return JobSnapshot(
        job_id=job_id,
        serial=str(row["serial"] or ""),
        command_line=str(row["command_line"] or ""),
        status=str(row["status"] or ""),
        started_at=parse_timestamp(row["started_at"]),
        last_event_at=parse_timestamp(last.created_at if last is not None else row["started_at"]),
        last_event_id=last.id if last is not None else None,
        error_events=count_error_events(events),
    )


def count_error_events(events: Iterable[Event]) -> int:
    """Count events that represent runtime or tool failures."""
    count = 0
    for event in events:
        # Include both framework failure topics and plugin-specific *.error
        # conventions so watchdog remains useful for third-party plugins.
        if event.topic in ERROR_TOPICS or event.topic.endswith(".error") or event.topic.endswith(".failed"):
            count += 1
    return count


def emit_once(
    context: CommandContext,
    parsed: Namespace,
    emitted: set[tuple[str, int]],
    topic: str,
    job: JobSnapshot,
    *,
    observed: float | int,
    threshold: float | int,
) -> None:
    """Emit one warning topic for one job at most once per watchdog invocation."""
    key = (topic, job.job_id)
    if key in emitted:
        return
    emitted.add(key)
    payload = {
        "job_id": job.job_id,
        "job_serial": job.serial,
        "status": job.status,
        "command_line": job.command_line,
        "observed": observed,
        "threshold": threshold,
        "last_event_id": job.last_event_id,
        "last_event_at": format_timestamp(job.last_event_at),
    }
    context.events.publish(topic, payload)
    context.alert(f"{topic}: job={job.job_id} observed={observed:.1f} threshold={threshold}", silent=parsed.silent)


def seconds_since(value: datetime | None, now: datetime) -> float | None:
    """Return seconds from `value` to `now`."""
    if value is None:
        return None
    return max(0.0, (now - value).total_seconds())


def parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO timestamp from SQLite rows/events."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime | None) -> str | None:
    """Return a stable ISO timestamp for event payloads."""
    return value.isoformat() if value is not None else None


def parse_bool(value: str | bool) -> bool:
    """Parse Bywaf boolean variable strings."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Watchdog()
