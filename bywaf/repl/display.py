"""Display helpers for REPL help, events, and runtime state.

Provides user-facing rendering for help text, event lists, history, jobs, steps,
triggers, commandlets, variables, and pager-backed generated output.

Used by:
- REPL command handlers: print command results without owning formatting.
- tests: patch pager dependencies and assert stable output."""


from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..event_filters import any_event_matches_payload_filters
from ..plugin import CommandContext
from ..rendering import Column, Table, render_console_table
from ..runtime_display import (
    ACTIVE_LISTING_FORMAT_VAR,
    commandlet_from_command_line,
    display_runtime_serial,
    format_runtime_timestamp,
    normalize_active_listing_format,
    render_table,
    runtime_state_label,
    runtime_state_text,
)
from ..runner import Runner
from ..secret.store import SECRET_REF_PREFIX, REDACTED_VALUE
from ..time_format import format_operator_timestamp, normalize_history_timestamp_for_display

VAR_COLOR_MODE_VAR = "display.vars.color"
VAR_NAME_COLOR_VAR = "display.vars.name-color"
VAR_VALUE_COLOR_VAR = "display.vars.value-color"
EVENT_COLOR_MODE_VAR = "display.events.color"
EVENT_KEY_COLOR_VAR = "display.events.key-color"
DISPLAY_STYLE_PREFIX = "display/style."
DISPLAY_COMMENT_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}comment"
DEFAULT_VAR_COLOR_MODE = "auto"
DEFAULT_VAR_NAME_COLOR = "cyan"
DEFAULT_VAR_VALUE_COLOR = "green"
DEFAULT_EVENT_COLOR_MODE = "auto"
DEFAULT_EVENT_KEY_COLOR = "green"
EVENT_HEADING_KEY_COLOR = "yellow"
EVENT_HEADING_VALUE_COLOR = "bright-blue"
EVENT_ID_COLOR = "bright-blue"
HISTORY_COLOR_MODE_VAR = "display.history.color"
HISTORY_TIMESTAMP_COLOR_VAR = "display.history.timestamp-color"
HELP_COLOR_MODE_VAR = "display.help.color"
HELP_COMMAND_COLOR_VAR = "display.help.command-color"
DEFAULT_HISTORY_COLOR_MODE = "auto"
DEFAULT_HISTORY_TIMESTAMP_COLOR = "green"
DEFAULT_HELP_COLOR_MODE = "auto"
DEFAULT_HELP_COMMAND_COLOR = "green"
EVENT_COMMANDLET_COLOR = "bright-yellow"

ANSI_COLORS = {
    "black": "30",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "bold-green": "1;32",
    "bold-yellow": "1;33",
    "bright-black": "90",
    "bright-red": "91",
    "bright-green": "1;32",
    "bright-yellow": "1;33",
    "bright-blue": "94",
    "bright-magenta": "95",
    "bright-cyan": "96",
    "bright-white": "97",
}

ANSI_STYLE_TOKENS = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "blink": "5",
    "reverse": "7",
    "strikethrough": "9",
}


# Built-in help lives here instead of in command handlers so display text,
# aliases, examples, and commandlet-delegated help have one owner.
@dataclass(frozen=True, slots=True)
class HelpEntry:
    """Help text for REPL built-ins that are not backed by commandlets."""

    command: str
    description: str
    usage: str
    examples: tuple[str, ...] = ()
    summary: str = ""


HELP_COMMANDS = (
    HelpEntry("help, ?", "show this help", "help [command]"),
    HelpEntry("plugins", "list loaded plugin providers", "plugins"),
    HelpEntry("cmds", "show commandlets grouped by plugin provider", "cmds"),
    HelpEntry("triggers", "show provider-owned trigger rules", "triggers"),
    HelpEntry("history", "show command history", "history"),
    HelpEntry("info", "show active jobs, pipelines, and steps", "info"),
    HelpEntry("jobs", "alias for job list", "jobs"),
    HelpEntry("pipelines", "alias for pipeline list", "pipelines"),
    HelpEntry("steps", "show commandlet pipeline steps", "steps"),
    HelpEntry("step <id|serial>", "inspect one commandlet pipeline step", "step <id|serial>", ("step 1", "step run-...")),
    HelpEntry("run", "execute the active commandlet selected by use", "run", ("use http_headers", "run")),
    HelpEntry(
        "set [--secret] [name[=value]]",
        "list, show, or set session variables",
        "set [--secret] [name[=value]]",
        (
            "set http/http_probe.cookie-file=/tmp/cookies.txt",
            "set --secret network/ssh_probe.password=client-password",
        ),
    ),
    HelpEntry("topics", "list event topics in the active database", "topics"),
    HelpEntry(
        "project, proj",
        "list, inspect, create, switch, archive, or export project directories",
        "project <list|info|new|use|archive|export>",
    ),
    HelpEntry("use <commandlet|global>", "set the active variable context", "use <commandlet|global>"),
    HelpEntry(
        "event",
        "show events for a topic, job, step, pipeline, serial, or event id",
        "event <id|topic|job=id|step=id|pipeline=id|serial=id> [field=value ...] [sort=key]",
        (
            "event 123",
            "event host.found",
            "event port.open host=192.0.2.10 sort=host",
            "event step=1",
            "event pipeline=1",
            "event serial=hostscanner-...",
        ),
        "event <selector>",
    ),
    HelpEntry("events [tail|--tail] [last=N]", "show recent events", "events [tail|--tail] [last=N]", ("events", "events tail", "events tail last=50")),
    HelpEntry("prompt [pattern]", "show or set prompt pattern", "prompt [pattern]", ("prompt $Y$M$D $h:$m:$s $Z> ",)),
    HelpEntry("plugin", "load filesystem plugins", "plugin load=<path> [--force]"),
    HelpEntry("pload", "short alias for plugin load", "pload <path> [--force]"),
    HelpEntry("config", "load or save session configuration", "config <load|save> file=<path> [--encrypt]"),
    HelpEntry("history", "show, load, or save command history", "history [since=... until=...] | history <load|save> file=<path> [--encrypt]"),
    HelpEntry("script", "load/run or save REPL scripts", "script <load|save> file=<path> [--encrypt]"),
    HelpEntry("exec <argv...>", "execute an OS command", "exec <argv...>", ("exec ls -la",)),
    HelpEntry("<plugin pipeline>", "run commandlets directly", "<plugin pipeline>", ("hostscanner 127.0.0.1 | portscanner",)),
    HelpEntry("exit, quit, q", "exit the shell", "exit"),
)


def format_event(event, runner: Runner | None = None) -> str:
    """Render one event row for human-readable console output."""
    # Prefer topic-specific summaries for high-volume operational events. The
    # fallback still exposes the raw payload for unknown third-party topics.
    if event.topic == "port.open":
        return format_port_open_event(event, runner)
    if event.topic == "host.found":
        return format_host_found_event(event, runner)
    if event.topic == "name.resolved":
        return format_name_resolved_event(event, runner)
    if event.topic == "console.alert":
        return format_console_alert_event(event)
    if event.topic in {"console.output", "framework.console.output.requested"}:
        return format_console_output_event(event)
    if event.topic == "framework.console.alert.requested":
        return format_console_alert_requested_event(event)
    if event.topic in {"plugin.capability.used", "plugin.capability.missing"}:
        return format_capability_event(event)
    if event.topic.startswith("plugin.progress."):
        return format_progress_event(event)
    if event.topic.startswith("command.run."):
        return format_command_run_event(event)
    if event.topic.startswith("job."):
        return format_job_event(event)
    if event.topic.startswith("framework.trigger."):
        return format_trigger_event(event)
    if event.topic == "framework.process.run.requested":
        return format_process_request_event(event)
    if event.topic in {"tool.error", "tool.exception", "system.error", "web.error", "network.error"}:
        return format_error_event(event)
    if event.topic == "runtime.name.assigned":
        return format_runtime_name_event(event)
    return f"{event.id}: {event.topic} {event.payload}"


def format_port_open_event(event, runner: Runner | None = None) -> str:
    """Render an open port as operator-facing evidence."""
    payload = event.payload
    host = semantic_text(runner, "host", payload.get("host", ""))
    port = semantic_text(runner, "port", payload.get("port", ""))
    protocol = semantic_text(runner, "protocol", payload.get("protocol", "tcp"))
    service = payload.get("service", "")
    reason = payload.get("reason", "")
    details = " ".join(str(value) for value in (service, reason) if value)
    suffix = f" {details}" if details else ""
    return f"{event.id}: port.open {host}:{port}/{protocol}{suffix}".strip()


def format_host_found_event(event, runner: Runner | None = None) -> str:
    """Render a discovered host as operator-facing evidence."""
    payload = event.payload
    host = semantic_text(runner, "host", payload.get("host", ""))
    name = payload.get("name", "")
    status = payload.get("status", "")
    scanner = payload.get("scanner", "")
    details = " ".join(str(value) for value in (name, status, scanner) if value)
    suffix = f" {details}" if details else ""
    return f"{event.id}: host.found {host}{suffix}".strip()


def format_name_resolved_event(event, runner: Runner | None = None) -> str:
    """Render DNS resolution provenance for scan targets."""
    payload = event.payload
    name = semantic_text(runner, "host.name", payload.get("name", ""))
    addresses = payload.get("addresses", ())
    if isinstance(addresses, list | tuple):
        address_text = ", ".join(semantic_text(runner, "host", address) for address in addresses)
    else:
        address_text = semantic_text(runner, "host", addresses)
    return f"{event.id}: name.resolved {name} -> {address_text}".strip()


def format_console_alert_event(event) -> str:
    """Render framework console alerts as readable operator messages."""
    payload = event.payload
    source = payload.get("source") or event.source
    level = payload.get("level", "alert")
    message = payload.get("message", "")
    return f"{event.id}: {source} {level}: {message}".rstrip(": ")


def format_console_alert_requested_event(event) -> str:
    """Render pending framework console alert requests."""
    payload = event.payload
    source = payload.get("source") or event.source
    level = payload.get("level", "alert")
    message = payload.get("message", "")
    return f"{event.id}: {source} alert requested {level}: {message}".rstrip(": ")


def format_console_output_event(event) -> str:
    """Render console output events without dumping large text payload dicts."""
    payload = event.payload
    source = payload.get("source") or event.source
    text = summarize_text(str(payload.get("text", "")))
    label = "output requested" if event.topic == "framework.console.output.requested" else "output"
    return f"{event.id}: {source} {label}: {text}".rstrip(": ")


def summarize_text(text: str, *, limit: int = 100) -> str:
    """Return the first non-empty line of console text, shortened for event tails."""
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if len(first_line) <= limit:
        return first_line
    return first_line[: limit - 1].rstrip() + "..."


def format_capability_event(event) -> str:
    """Render capability audit events compactly."""
    payload = event.payload
    commandlet = payload.get("commandlet") or event.source
    capability = payload.get("capability", "")
    declared = payload.get("declared")
    status = "declared" if declared else "missing"
    if event.topic == "plugin.capability.missing":
        status = "missing"
    return f"{event.id}: {commandlet} capability {capability} {status}".strip()


def format_progress_event(event) -> str:
    """Render progress events without dumping the full payload."""
    payload = event.payload
    commandlet = payload.get("commandlet") or event.source
    status = payload.get("status") or event.topic.rsplit(".", 1)[-1]
    phase = payload.get("phase", "")
    message = payload.get("message", "")
    summary_parts = [
        f"{payload.get('current')}/{payload.get('total')} {payload.get('unit')}"
        if payload.get("current") is not None and payload.get("total") is not None and payload.get("unit")
        else "",
        f"{payload.get('percent')}%" if payload.get("percent") is not None else "",
        f"open_ports={payload.get('open_ports')}" if payload.get("open_ports") is not None else "",
    ]
    summary = " ".join(part for part in summary_parts if part)
    tail = " ".join(part for part in (message, summary) if part)
    return f"{event.id}: {commandlet} {phase} {status}: {tail}".rstrip(": ")


def format_command_run_event(event) -> str:
    """Render pipeline-step lifecycle events compactly."""
    payload = event.payload
    commandlet = payload.get("commandlet") or event.source
    status = payload.get("status") or event.topic.rsplit(".", 1)[-1]
    emitted = payload.get("emitted")
    emitted_text = f" emitted={emitted}" if emitted is not None else ""
    return f"{event.id}: {commandlet} {status}{emitted_text}"


def format_job_event(event) -> str:
    """Render job lifecycle events compactly."""
    payload = event.payload
    job_id = payload.get("job_id", "")
    command = payload.get("command", "")
    topic = event.topic.removeprefix("job.")
    started_at = payload.get("started_at", "")
    started_text = f" launched={format_runtime_timestamp(started_at)}" if started_at else ""
    commandlet_text = f" commandlet={commandlet_from_command_line(str(command))}" if command else ""
    command_text = f" command={command}" if command else ""
    error = payload.get("error", "")
    error_text = f" error={error}" if error else ""
    return f"{event.id}: job {job_id} {topic}{started_text}{commandlet_text}{command_text}{error_text}".strip()

def format_trigger_event(event) -> str:
    """Render trigger lifecycle events compactly."""
    payload = event.payload
    action = event.topic.removeprefix("framework.trigger.")
    trigger = payload.get("trigger_id") or payload.get("name") or ""
    command = payload.get("action_command", "")
    caused_by = payload.get("trigger_event_topic", "")
    suffix = f" -> {command}" if command else ""
    if caused_by:
        suffix += f" from {caused_by}"
    return f"{event.id}: trigger {action} {trigger}{suffix}".strip()


def format_process_request_event(event) -> str:
    """Render framework process requests without dumping argv arrays."""
    payload = event.payload
    source = payload.get("source") or event.source
    argv = payload.get("argv", [])
    command = " ".join(str(part) for part in argv) if isinstance(argv, list) else str(argv)
    timeout = payload.get("timeout")
    timeout_text = f" timeout={timeout}" if timeout is not None else ""
    return f"{event.id}: {source} process requested: {summarize_text(command, limit=140)}{timeout_text}".rstrip()


def format_error_event(event) -> str:
    """Render tool/system error events as a single readable line."""
    payload = event.payload
    source = payload.get("tool") or payload.get("source") or event.source
    severity = payload.get("severity", "error")
    message = payload.get("message") or payload.get("error") or ""
    return f"{event.id}: {source} {severity}: {message}".rstrip(": ")


def format_runtime_name_event(event) -> str:
    """Render runtime naming events."""
    payload = event.payload
    target_type = payload.get("target_type", "")
    target_id = payload.get("target_id", "")
    name = payload.get("name", "")
    return f"{event.id}: {target_type} {target_id} named {name}".strip()


def friendly_error(exc: Exception) -> str:
    """Normalize exception text for REPL display."""
    if isinstance(exc, KeyError):
        return str(exc).strip("'")
    return str(exc)


def print_events(events, runner: Runner | None = None) -> None:
    """Print persisted events in a compact inspectable form."""
    for event in events:
        print(format_event_listing_line(runner, event, format_event(event, runner)))


def format_event_listing_line(runner: Runner | None, event, line: str) -> str:
    """Color the event id and commandlet name at the start of a compact event row."""
    if runner is None or not event_color_enabled(runner):
        return line
    event_id, separator, rest = line.partition(": ")
    if not separator:
        return line
    return f"{ansi_color(event_id, EVENT_ID_COLOR)}: {color_event_listing_commandlet(event, rest)}"


def color_event_listing_commandlet(event, text: str) -> str:
    """Color commandlet names in compact event rows when they are identifiable."""
    commandlet = event.payload.get("commandlet") or event.payload.get("source")
    if not commandlet and event.source not in {"framework", "runner", "test"}:
        commandlet = event.source
    if not commandlet:
        return text
    commandlet_text = str(commandlet)
    colored = ansi_color(commandlet_text, EVENT_COMMANDLET_COLOR)
    if text.startswith(f"{commandlet_text} "):
        return f"{colored}{text[len(commandlet_text):]}"
    if text.startswith(f"{commandlet_text}:"):
        return f"{colored}{text[len(commandlet_text):]}"
    return text.replace(f"commandlet={commandlet_text}", f"commandlet={colored}", 1)


def print_event_info(runner: Runner, event_id_text: str) -> None:
    """Print one event with runtime context and readable payload fields."""
    try:
        event_id = int(event_id_text)
    except ValueError:
        print(f"error: invalid event id: {event_id_text}")
        return
    event = runner.events.event_by_id(event_id)
    if event is None:
        print(f"error: unknown event: {event_id}")
        return
    payload = event.payload
    # Detail view is deliberately layered: identity first, then provenance,
    # then causality, then raw payload fields.
    print(format_event_heading(runner, event.id))
    print(format_event_kv(runner, "Topic", event.topic))
    print(format_event_kv(runner, "Created", format_event_timestamp(event.created_at)))
    print(format_event_kv(runner, "Source", event.source))
    print(format_event_kv(runner, "Actor", event_actor(event.source, event.topic, payload)))
    print_event_scope(runner, event, payload)
    print_event_job_context(runner, payload)
    print_event_command_context(runner, payload, event.command_run_id)
    print_event_causality(runner, payload)
    print_event_payload(runner, payload)


def format_event_timestamp(value: datetime) -> str:
    """Render full event time in the operator's local timezone."""
    return format_operator_timestamp(value)


def format_event_heading(runner: Runner, event_id: int | None) -> str:
    """Return the highlighted detail heading for one event."""
    if not event_color_enabled(runner):
        return f"Event ID: {event_id}"
    return (
        f"{ansi_color('Event ID', EVENT_HEADING_KEY_COLOR)}: "
        f"{ansi_color(str(event_id), EVENT_HEADING_VALUE_COLOR)}"
    )


def event_actor(source: str, topic: str, payload: dict[str, Any]) -> str:
    """Infer the component most likely responsible for an event."""
    if topic.startswith("framework.trigger."):
        trigger_id = payload.get("trigger_id") or payload.get("name")
        return f"trigger:{trigger_id}" if trigger_id else "trigger"
    commandlet = payload.get("commandlet")
    if commandlet:
        return f"commandlet:{commandlet}"
    if source in {"framework", "runner"}:
        return source
    return f"plugin:{source}"


def print_event_scope(runner: Runner, event, payload: dict[str, Any]) -> None:
    """Print job, pipeline, step, and parent-step scope for an event."""
    scope = {
        "Job": payload.get("job_id"),
        "Pipeline": event.pipeline_id or payload.get("pipeline_id"),
        "Step": event.command_run_id or payload.get("command_run_id"),
        "Parent step": event.parent_command_run_id or payload.get("parent_command_run_id"),
    }
    rows = [(label, value) for label, value in scope.items() if value not in (None, "")]
    if not rows:
        return
    print(format_event_section_header(runner, "Scope"))
    for label, value in rows:
        print(format_event_kv(runner, label, value, prefix="  "))


def print_event_job_context(runner: Runner, payload: dict[str, Any]) -> None:
    """Print the job row associated with an event payload, when present."""
    job_id = payload.get("job_id")
    if job_id in (None, ""):
        return
    try:
        job = runner.runtime.job(int(job_id))
    except (TypeError, ValueError):
        job = None
    if job is None:
        print(format_event_kv(runner, "Job", "missing"))
        return
    command = str(job["command_line"] or "")
    print(format_event_section_header(runner, "Job"))
    print(format_event_kv(runner, "ID", job["id"], prefix="  "))
    print(format_event_kv(runner, "Serial", display_runtime_serial(job["serial"]), prefix="  "))
    print(format_event_kv(runner, "Status", job["status"], prefix="  "))
    if job["started_at"]:
        print(format_event_kv(runner, "Launched", format_event_timestamp(datetime.fromisoformat(job["started_at"])), prefix="  "))
    if job["finished_at"]:
        print(format_event_kv(runner, "Finished", format_event_timestamp(datetime.fromisoformat(job["finished_at"])), prefix="  "))
    if command:
        print(format_event_kv(runner, "Commandlet", commandlet_from_command_line(command), prefix="  "))
        print(format_event_kv(runner, "Command", command, prefix="  "))


def print_event_command_context(runner: Runner, payload: dict[str, Any], command_run_id: str | None) -> None:
    """Print pipeline-step context from payload or its argument event."""
    run_id = command_run_id or payload.get("command_run_id")
    command = payload.get("command")
    commandlet = payload.get("commandlet")
    args: list[Any] | None = None
    launched: str | None = None
    if run_id and (commandlet is None or command is None):
        # Many events only carry a step id. Look up the framework-owned
        # command.run.arguments event to recover commandlet/arg context.
        matches = runner.events.events_matching(topic="command.run.arguments", command_run_id=str(run_id), limit=1)
        if matches:
            args_payload = matches[0].payload
            commandlet = commandlet or args_payload.get("commandlet")
            args_value = args_payload.get("args")
            args = args_value if isinstance(args_value, list) else None
            launched = format_event_timestamp(matches[0].created_at)
    if not any((run_id, commandlet, command, args, launched)):
        return
    print(format_event_section_header(runner, "Command"))
    if run_id:
        print(format_event_kv(runner, "Run", run_id, prefix="  "))
    if launched:
        print(format_event_kv(runner, "Launched", launched, prefix="  "))
    if commandlet:
        print(format_event_kv(runner, "Commandlet", commandlet, prefix="  "))
    if command:
        print(format_event_kv(runner, "Line", command, prefix="  "))
    if args is not None:
        print(format_event_kv(runner, "Args", " ".join(str(arg) for arg in args), prefix="  "))


def print_event_causality(runner: Runner, payload: dict[str, Any]) -> None:
    """Print event ids that this event claims as its cause."""
    cause_fields = (
        ("Request event", "request_event_id"),
        ("Trigger event", "trigger_event_id"),
        ("Parent event", "parent_event_id"),
    )
    rows = [(label, payload[key]) for label, key in cause_fields if payload.get(key) not in (None, "")]
    if not rows:
        return
    print(format_event_section_header(runner, "Cause"))
    for label, value in rows:
        print(format_event_kv(runner, label, value, prefix="  "))


def print_event_payload(runner: Runner, payload: dict[str, Any]) -> None:
    """Print payload fields as readable key/value rows."""
    if not payload:
        return
    print(format_event_section_header(runner, "Payload"))
    for key in sorted(payload):
        print(format_event_kv(runner, key, format_payload_value(payload[key]), prefix="  "))


def format_event_kv(runner: Runner, key: str, value: object, *, prefix: str = "") -> str:
    """Return an event detail key/value row with optional colored keys."""
    if not event_color_enabled(runner):
        return f"{prefix}{key}: {value}"
    key_color = runner.registry.varstore.get(EVENT_KEY_COLOR_VAR, DEFAULT_EVENT_KEY_COLOR) or DEFAULT_EVENT_KEY_COLOR
    return f"{prefix}{ansi_color(key, key_color)}: {format_event_value(key, value)}"


def format_event_value(key: str, value: object) -> str:
    """Return special value styling for event detail fields."""
    text = str(value)
    if key.casefold() == "commandlet":
        return ansi_color(text, EVENT_COMMANDLET_COLOR)
    return text


def format_event_section_header(runner: Runner, label: str) -> str:
    """Return a highlighted section header for event detail output."""
    if not event_color_enabled(runner):
        return f"{label}:"
    return f"{ansi_color(label, EVENT_HEADING_KEY_COLOR)}:"


def event_color_enabled(runner: Runner) -> bool:
    """Return whether event detail listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(EVENT_COLOR_MODE_VAR, DEFAULT_EVENT_COLOR_MODE) or DEFAULT_EVENT_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def format_payload_value(value: Any) -> str:
    """Render nested payload values without a one-line raw dict dump."""
    if isinstance(value, list | tuple):
        return ", ".join(format_payload_value(item) for item in value)
    if isinstance(value, dict):
        # Sort nested keys so event detail output remains stable across Python
        # versions and plugin payload construction order.
        return ", ".join(f"{key}={format_payload_value(value[key])}" for key in sorted(value))
    return str(value)


def print_run_variables(runner: Runner, command_run_id: str) -> None:
    """Print the variable snapshot captured for a pipeline step."""
    rows = runner.runtime.command_run_var_rows(command_run_id)
    if not rows:
        return
    print("Variables:")
    for row in rows:
        print(format_var_assignment(runner, row["name"], row["value"], prefix="  "))


def print_history(
    entries: Sequence[str] = (),
    selectors: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> None:
    """Print the current session history, optionally filtered by time bounds."""
    window = history_time_window(selectors or {})
    for entry in entries:
        if history_entry_in_window(entry, window):
            print(format_history_entry_for_display(entry, runner))


def format_history_entry_for_display(entry: str, runner: Runner | None = None) -> str:
    """Display script-friendly history as timestamp-first for readability."""
    command, separator, timestamp = entry.rpartition("  # ")
    if not separator or not timestamp:
        return entry
    display_timestamp = normalize_history_timestamp_for_display(timestamp)
    comment_style = runner.registry.varstore.get(DISPLAY_COMMENT_STYLE_VAR, "") if runner is not None else ""
    if runner is not None and comment_style:
        display_timestamp = ansi_color(display_timestamp, comment_style)
    elif runner is not None and history_color_enabled(runner):
        color = (
            runner.registry.varstore.get(HISTORY_TIMESTAMP_COLOR_VAR, DEFAULT_HISTORY_TIMESTAMP_COLOR)
            or DEFAULT_HISTORY_TIMESTAMP_COLOR
        )
        display_timestamp = ansi_color(display_timestamp, color)
    return f"{display_timestamp}  {command}"


def history_color_enabled(runner: Runner) -> bool:
    """Return whether history listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(HISTORY_COLOR_MODE_VAR, DEFAULT_HISTORY_COLOR_MODE) or DEFAULT_HISTORY_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def history_time_window(selectors: dict[str, str]) -> tuple[str | None, str | None]:
    """Convert history selectors to inclusive compact timestamp bounds."""
    # Bounds compare as YYYYMMDDHHMMSS strings, which preserves chronological
    # order without needing timezone reconstruction for history comments.
    since = normalize_history_time_bound(selectors["since"], until=False) if "since" in selectors else None
    until = normalize_history_time_bound(selectors["until"], until=True) if "until" in selectors else None
    return since, until


def normalize_history_time_bound(value: str, *, until: bool) -> str:
    """Normalize `yyyymmdd[HH[MM[SS]]]` or `time:<...>` to YYYYMMDDHHMMSS."""
    if ":" in value:
        kind, raw = value.split(":", 1)
        if kind != "time":
            raise ValueError("history since=/until= only supports time bounds")
    else:
        raw = value
    digits = "".join(char for char in raw if char.isdigit())
    if len(digits) not in {8, 10, 12, 14}:
        raise ValueError("history time must be yyyymmdd[HH[MM[SS]]]")
    if len(digits) == 8:
        return digits + ("235959" if until else "000000")
    if len(digits) == 10:
        return digits + ("5959" if until else "0000")
    if len(digits) == 12:
        return digits + ("59" if until else "00")
    return digits


def history_entry_in_window(entry: str, window: tuple[str | None, str | None]) -> bool:
    """Return whether a script-friendly history entry falls within a time window."""
    since, until = window
    _command, separator, timestamp = entry.rpartition("  # ")
    if not separator:
        return since is None and until is None
    compact = "".join(char for char in timestamp if char.isdigit())
    if len(compact) < 14:
        return since is None and until is None
    compact = compact[:14]
    return (since is None or compact >= since) and (until is None or compact <= until)


def print_help(runner: Runner, command: str | None = None) -> None:
    """Print built-in help or delegate commandlet help."""
    if command:
        print_command_help(runner, command)
        return
    width = max(len(entry.summary or entry.command) for entry in HELP_COMMANDS)
    for entry in HELP_COMMANDS:
        command = entry.summary or entry.command
        command_text = f"{command:<{width}}"
        print(f"{format_help_command(runner, command_text)}  {entry.description}")


def print_command_help(runner: Runner, command: str) -> None:
    """Show help for either a plugin commandlet or shell built-in."""
    plugin = runner.registry.plugins.get(command)
    if plugin:
        print_plugin_argparse_help(runner, plugin)
        return
    entry = find_help_entry(command)
    if entry:
        print_help_entry(runner, entry)
        return
    print(f"error: unknown command: {command}")


def find_help_entry(command: str) -> HelpEntry | None:
    """Find built-in help by command name or alias."""
    for entry in HELP_COMMANDS:
        aliases = [part.strip().split()[0] for part in entry.command.split(",")]
        if command in aliases:
            return entry
    return None


def print_help_entry(runner: Runner, entry: HelpEntry) -> None:
    """Render one built-in help entry."""
    print(f"Command: {format_help_command(runner, entry.command)}")
    print(f"Usage:   {entry.usage}")
    if entry.examples:
        print("Examples:")
        for example in entry.examples:
            print(f"  {example}")
    print()
    print(entry.description)


def format_help_command(runner: Runner | None, command: str) -> str:
    """Return a built-in help command name with optional ANSI color."""
    if runner is None or not help_color_enabled(runner):
        return command
    color = runner.registry.varstore.get(HELP_COMMAND_COLOR_VAR, DEFAULT_HELP_COMMAND_COLOR) or DEFAULT_HELP_COMMAND_COLOR
    return ansi_color(command, color)


def help_color_enabled(runner: Runner) -> bool:
    """Return whether help listings should include ANSI color escapes."""
    mode = (
        runner.registry.varstore.get(HELP_COLOR_MODE_VAR, DEFAULT_HELP_COLOR_MODE) or DEFAULT_HELP_COLOR_MODE
    ).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def print_plugin_argparse_help(runner: Runner, plugin) -> None:
    """Ask a commandlet's argparse parser to print its native help."""
    # Commandlets own their argparse help text. Running with --help keeps docs
    # and runtime parsing aligned, while catching SystemExit below avoids
    # tearing down the REPL on successful help output.
    context = CommandContext(
        runner.db,
        source=plugin.spec.name,
        _varstore=runner.registry.varstore,
        _secrets=runner.registry.secrets,
    )
    try:
        list(plugin.run(context, ["--help"], []))
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise


def print_jobs(runner: Runner) -> None:
    """Print known background jobs."""
    runtime = runner.runtime
    names = runtime.runtime_names()
    artifact_counts = runtime.artifact_counts_by_job()
    rows = [
        (
            row["id"],
            display_runtime_serial(row["serial"]),
            row["pid"],
            row["status"],
            artifact_counts.get(str(row["id"]), 0),
            names.get(("job", str(row["id"])), ""),
            format_runtime_timestamp(row["started_at"]),
            format_runtime_timestamp(row["finished_at"]),
            row["command_line"],
        )
        for row in runtime.jobs()
    ]
    if rows:
        print(render_table(("JOB", "SERIAL", "PID", "STATUS", "ARTIFACTS", "NAME", "STARTED", "FINISHED", "COMMAND"), rows))


def print_info(runner: Runner) -> None:
    """Print a compact runtime dashboard for entities currently in play."""
    runtime = runner.runtime
    print(f"Jobs ({len(runtime.jobs(active_only=True))})")
    # Reuse runtime commandlets for jobs/pipelines so `info` does not maintain
    # a separate table format from the primary commands.
    events = runner.execute("job list")
    process_events_for_non_repl_info(runner, events)
    print()
    print(f"Pipelines ({len(runtime.pipelines(active_only=True))})")
    events = runner.execute("pipeline list")
    process_events_for_non_repl_info(runner, events)
    print()
    print(f"Steps ({len(runtime.runs(active_only=True))})")
    print_runs(runner)


def process_events_for_non_repl_info(runner: Runner, events) -> None:
    """Print framework output events emitted by commandlets during `info`."""
    del runner
    for event in events:
        if event.topic == "framework.console.output.requested":
            print(event.payload.get("text", ""), end=event.payload.get("end", "\n"))


def print_runs(runner: Runner, *, active_only: bool = True, filters: dict[str, str] | None = None) -> None:
    """Print commandlet step summaries."""
    runtime = runner.runtime
    rows = runtime.runs(active_only=active_only)
    if filters:
        rows = [
            row
            for row in rows
            if any_event_matches_payload_filters(
                runner.events.events_matching(command_run_id=str(row["command_run_id"]), limit=10000),
                filters,
            )
        ]
    if not rows:
        print("no matching steps" if filters else "no active steps" if active_only else "no steps")
        return
    marker_style = normalize_active_listing_format(
        runner.registry.varstore.get(f"global.{ACTIVE_LISTING_FORMAT_VAR}")
    )
    names = runtime.runtime_names()
    run_aliases = runtime.run_aliases()
    pipeline_aliases = runtime.pipeline_aliases()
    artifact_counts = runtime.artifact_counts_by_run()
    table_rows: list[tuple[object, ...]] = []
    for row in rows:
        run_serial = str(row["command_run_id"])
        pipeline_serial = str(row["pipeline_id"]) if row["pipeline_id"] is not None else ""
        pipeline_alias = pipeline_aliases.get(pipeline_serial, "")
        label = runtime_state_label(row["job_statuses"])
        # Active rows are more useful with their first event time; completed
        # rows are more useful with the latest event/finish time.
        timestamp = row["first_event"] if label in {"active", "in progress"} else row["last_event"]
        table_rows.append(
            (
                run_aliases.get(run_serial, run_serial),
                display_runtime_serial(run_serial),
                runtime_state_text(row["job_statuses"], timestamp, style=marker_style),
                names.get(("run", run_serial), ""),
                pipeline_alias,
                display_runtime_serial(pipeline_serial),
                row["source"],
                row["events"],
                artifact_counts.get(run_serial, 0),
                format_runtime_timestamp(row["first_event"]),
                format_runtime_timestamp(row["last_event"]),
            )
        )
    print(
        render_table(
            ("STEP", "SERIAL", "STATE", "NAME", "PIPELINE", "PIPELINE_SERIAL", "SOURCE", "EVENTS", "ARTIFACTS", "FIRST", "LAST"),
            table_rows,
        )
    )


def print_job(runner: Runner, job_id: str) -> None:
    """Print one job row by ID."""
    runtime = runner.runtime
    names = runtime.runtime_names()
    for row in runtime.jobs():
        if str(row["id"]) == job_id:
            print(
                f"#{row['id']} serial={row['serial']} pid={row['pid']} status={row['status']}"
                f"{format_runtime_name(names.get(('job', str(row['id']))))}"
                f" launched={format_runtime_timestamp(row['started_at'])}"
                f" finished={format_runtime_timestamp(row['finished_at'])}"
                f" commandlet={commandlet_from_command_line(str(row['command_line']))}"
                f" command={row['command_line']}"
            )
            return
    print(f"error: unknown job: {job_id}")


def format_runtime_name(display_name: str | None) -> str:
    """Return a compact runtime name fragment for listings."""
    return f" name={display_name}" if display_name else ""


def display_var_value(runner: Runner, value: str) -> str:
    """Return a variable value with in-memory secret references redacted."""
    secret_ref = runner.registry.secrets.metadata(value)
    if secret_ref is None:
        if value.startswith(SECRET_REF_PREFIX):
            # A secret ref may exist in persisted config before the cleartext has
            # been hydrated into this process.
            return f"{REDACTED_VALUE} fingerprint=unavailable"
        return value
    return f"{REDACTED_VALUE} fingerprint={secret_ref.fingerprint.format()}"


def format_var_assignment(runner: Runner, name: str, value: str, *, prefix: str = "") -> str:
    """Return a `name=value` variable row with optional ANSI color."""
    displayed_value = display_var_value(runner, value)
    if not vars_color_enabled(runner):
        return f"{prefix}{name}={displayed_value}"
    name_color = runner.registry.varstore.get(VAR_NAME_COLOR_VAR, DEFAULT_VAR_NAME_COLOR) or DEFAULT_VAR_NAME_COLOR
    value_color = runner.registry.varstore.get(VAR_VALUE_COLOR_VAR, DEFAULT_VAR_VALUE_COLOR) or DEFAULT_VAR_VALUE_COLOR
    return f"{prefix}{ansi_color(name, name_color)}={ansi_var_value(displayed_value, value_color)}"


def vars_color_enabled(runner: Runner) -> bool:
    """Return whether variable listings should include ANSI color escapes."""
    mode = (runner.registry.varstore.get(VAR_COLOR_MODE_VAR, DEFAULT_VAR_COLOR_MODE) or DEFAULT_VAR_COLOR_MODE).casefold()
    if mode in {"0", "false", "no", "never", "off", "plain"}:
        return False
    if mode in {"1", "true", "yes", "always", "on"}:
        return True
    return sys.stdout.isatty()


def ansi_color(text: str, color: str) -> str:
    """Wrap text in an ANSI SGR color when the requested color is known."""
    code = ansi_style_code(color)
    if code is None:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def semantic_text(runner: Runner | None, role: str, value: object) -> str:
    """Render a value using a user-configured semantic display role."""
    text = str(value)
    if runner is None:
        return text
    style = runner.registry.varstore.get(f"{DISPLAY_STYLE_PREFIX}{role}", "")
    if not style and "." in role:
        style = runner.registry.varstore.get(f"{DISPLAY_STYLE_PREFIX}{role.rsplit('.', 1)[0]}", "")
    if not style:
        return text
    return ansi_color(text, style)


def ansi_style_code(style: str) -> str | None:
    """Return one combined ANSI SGR sequence for color plus text attributes."""
    codes: list[str] = []
    for token in style.split():
        normalized = token.strip().casefold().replace("_", "-")
        if not normalized:
            continue
        if normalized in ANSI_STYLE_TOKENS:
            codes.append(ANSI_STYLE_TOKENS[normalized])
            continue
        color_code = ansi_color_code(normalized)
        if color_code is not None:
            codes.append(color_code)
    return ";".join(codes) if codes else None


def ansi_color_code(color: str) -> str | None:
    """Return an SGR color code for a named, 256-color, or truecolor setting."""
    normalized = color.strip().casefold().replace("_", "-")
    if not normalized:
        return None
    if normalized in ANSI_COLORS:
        return ANSI_COLORS[normalized]
    if normalized.startswith("color"):
        number = parse_color_int(normalized.removeprefix("color"), 0, 255)
        return f"38;5;{number}" if number is not None else None
    if normalized.startswith("#"):
        rgb = parse_hex_color(normalized)
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("ansi:"):
        # ansi:N and rgb:R,G,B let users customize colors without expanding the
        # named-color table for every possible terminal.
        number = parse_color_int(normalized.removeprefix("ansi:"), 0, 255)
        return f"38;5;{number}" if number is not None else None
    if normalized.startswith("bg-ansi:"):
        number = parse_color_int(normalized.removeprefix("bg-ansi:"), 0, 255)
        return f"48;5;{number}" if number is not None else None
    if normalized.startswith("rgb:"):
        rgb = parse_rgb_color(normalized.removeprefix("rgb:"))
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("bg-rgb:"):
        rgb = parse_rgb_color(normalized.removeprefix("bg-rgb:"))
        return f"48;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    return None


def parse_hex_color(raw: str) -> tuple[int, int, int] | None:
    """Parse CSS-style `#RRGGBB` and `#RGB` colors for truecolor output."""
    value = raw.strip().removeprefix("#")
    if len(value) == 3:
        value = "".join(component * 2 for component in value)
    if len(value) != 6 or any(char not in "0123456789abcdef" for char in value):
        return None
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def parse_rgb_color(raw: str) -> tuple[int, int, int] | None:
    """Parse `R,G,B` values for truecolor terminal output."""
    parts = raw.split(",")
    if len(parts) != 3:
        return None
    red = parse_color_int(parts[0], 0, 255)
    green = parse_color_int(parts[1], 0, 255)
    blue = parse_color_int(parts[2], 0, 255)
    if red is None or green is None or blue is None:
        return None
    return red, green, blue


def parse_color_int(raw: str, minimum: int, maximum: int) -> int | None:
    """Parse one bounded color integer."""
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    if minimum <= value <= maximum:
        return value
    return None


def ansi_var_value(text: str, color: str) -> str:
    """Wrap variable values, giving redacted secrets a warning-style badge."""
    if not text.startswith(REDACTED_VALUE):
        return ansi_color(text, color)
    suffix = text.removeprefix(REDACTED_VALUE)
    return f"{ansi_secret_redaction(REDACTED_VALUE)}{ansi_color(suffix, color)}"


def ansi_secret_redaction(text: str) -> str:
    """Render redacted secret text as white on a dark red background."""
    return f"\x1b[37;48;5;52m{text}\x1b[0m"


def print_topics(runner: Runner, prefix: str = "") -> None:
    """Print event topics known to the active database, optionally filtered."""
    matched = [topic for topic in runner.events.topics() if topic.startswith(prefix)]
    for topic in matched:
        print(topic)
    if prefix and not matched:
        print(f"no matching topics: {prefix}")


def print_plugins(runner: Runner) -> None:
    """Print loaded plugin providers with compact purpose summaries."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        rows.append(
            {
                "provider": provider,
                "count": str(len(commandlets)),
                "description": provider_description(provider, commandlets, runner),
            }
        )
    if rows:
        print(
            render_console_table(
                Table(
                    (
                        Column("provider", "PLUGIN"),
                        Column("count", "CMDS"),
                        Column("description", "WHAT IT DOES"),
                    ),
                    tuple(rows),
                )
            )
        )


def provider_description(provider: str, commandlets: list[str], runner: Runner) -> str:
    """Return a compact readable provider description."""
    override = provider_descriptions().get(provider)
    if override is not None:
        return override
    if len(commandlets) == 1:
        return runner.registry.plugins[commandlets[0]].spec.description
    return f"{len(commandlets)} commandlets; run `cmds` for command-level details."


def provider_descriptions() -> dict[str, str]:
    """Return concise descriptions for bundled provider groups."""
    return {
        "analysis": "Finding normalization, reporting, and file-analysis helpers.",
        "discovery": "Host and target discovery commandlets.",
        "http": "HTTP probing, fingerprinting, screenshot, and Nikto wrappers.",
        "identity": "Identity and directory-service probes.",
        "network": "Network service discovery and protocol probes.",
        "os": "Local filesystem inspection helpers.",
        "recon": "External and DNS reconnaissance helpers.",
        "runtime": "Core runtime, audit, artifact, bundle, key, and control commands.",
        "storage": "Database storage management.",
        "wireless": "Wireless scanning wrappers.",
    }


def print_commandlets(runner: Runner, *, page: bool = False) -> None:
    """Print commandlets grouped under their plugin providers."""
    lines = render_commandlets(runner)
    if page:
        page_generated_text("\n".join(lines))
        return
    print("\n".join(lines))


def print_triggers(runner: Runner) -> None:
    """Print provider-owned trigger rules."""
    if not runner.registry.triggers:
        print("no triggers loaded")
        return
    states = {str(row["name"]): row for row in runner.db.trigger_states()}
    rows = []
    for trigger in sorted(runner.registry.triggers, key=lambda item: runner.registry.trigger_id(item)):
        trigger_id = runner.registry.trigger_id(trigger)
        state = states.get(trigger_id)
        rows.append(
            {
                "provider": runner.registry.trigger_provider(trigger) or "",
                "name": trigger.name,
                "topic": trigger.topic,
                "action": trigger.action_command,
                "mode": trigger.action_mode,
                "cursor": str(state["last_event_id"]) if state is not None else "0",
            }
        )
    print(
        render_console_table(
            Table(
                (
                    Column("provider", "PROVIDER"),
                    Column("name", "TRIGGER"),
                    Column("topic", "TOPIC"),
                    Column("action", "ACTION"),
                    Column("mode", "MODE"),
                    Column("cursor", "CURSOR"),
                ),
                tuple(rows),
            )
        )
    )


def render_commandlets(runner: Runner) -> list[str]:
    """Return commandlets grouped under their plugin providers as a table."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        for commandlet in commandlets:
            plugin = runner.registry.plugins[commandlet]
            rows.append(
                {
                    "provider": provider,
                    "commandlet": commandlet,
                    "description": plugin.spec.description,
                }
            )
    if not rows:
        return []
    return [
        render_console_table(
            Table(
                (
                    Column("provider", "PLUGIN"),
                    Column("commandlet", "COMMANDLET"),
                    Column("description", "WHAT IT DOES"),
                ),
                tuple(rows),
            )
        )
    ]


def page_generated_text(text: str) -> None:
    """Page built-in generated text through the system pager when available."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write(text)
        if text and not text.endswith("\n"):
            handle.write("\n")
        path = Path(handle.name)
    try:
        pager = shutil.which("less")
        if pager and sys.stdin.isatty() and sys.stdout.isatty():
            # Use an external pager only for interactive terminals; test and
            # redirected output should receive plain stdout.
            subprocess.run([pager, str(path)], check=False)
            return
        print(path.read_text(errors="replace"), end="", flush=True)
    finally:
        path.unlink(missing_ok=True)
