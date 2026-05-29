"""Compact event display rendering.

Provides one-line event rows and event-specific syntax styling.

Used by:
- repl.commands: implement `events` and compact topic listings.
- shell helpers: show commandlet output events after non-REPL calls."""

from __future__ import annotations

from ...runtime_display import commandlet_from_command_line, format_runtime_timestamp
from ...runner import Runner
from ...style import ansi_color
from .detail import event_color_enabled
from .settings import (
    DISPLAY_STRING_STYLE_VAR,
    EVENT_COMMANDLET_COLOR,
    EVENT_ID_COLOR,
)
from .variables import subject_text

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
    host = subject_text(runner, "host", payload.get("host", ""))
    port = subject_text(runner, "port", payload.get("port", ""))
    protocol = subject_text(runner, "protocol", payload.get("protocol", "tcp"))
    service = payload.get("service", "")
    reason = payload.get("reason", "")
    details = " ".join(str(value) for value in (service, reason) if value)
    suffix = f" {details}" if details else ""
    return f"{event.id}: port.open {host}:{port}/{protocol}{suffix}".strip()


def format_host_found_event(event, runner: Runner | None = None) -> str:
    """Render a discovered host as operator-facing evidence."""
    payload = event.payload
    host = subject_text(runner, "host", payload.get("host", ""))
    name = payload.get("name", "")
    status = payload.get("status", "")
    scanner = payload.get("scanner", "")
    details = " ".join(str(value) for value in (name, status, scanner) if value)
    suffix = f" {details}" if details else ""
    return f"{event.id}: host.found {host}{suffix}".strip()


def format_name_resolved_event(event, runner: Runner | None = None) -> str:
    """Render DNS resolution provenance for scan targets."""
    payload = event.payload
    name = subject_text(runner, "host.name", payload.get("name", ""))
    if "host" in payload:
        address_text = subject_text(runner, "host", payload.get("host", ""))
        return f"{event.id}: name.resolved {name} -> {address_text}".strip()
    addresses = payload.get("addresses", ())
    if isinstance(addresses, list | tuple):
        address_text = ", ".join(subject_text(runner, "host", address) for address in addresses)
    else:
        address_text = subject_text(runner, "host", addresses)
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
    """Color a compact event row using configured event and subject styles."""
    if runner is None:
        return line
    if not event_color_enabled(runner):
        return style_quoted_strings(runner, line)
    event_id, separator, rest = line.partition(": ")
    if not separator:
        return style_quoted_strings(runner, line)
    styled = f"{ansi_color(event_id, EVENT_ID_COLOR)}: {color_event_listing_commandlet(event, rest)}"
    return style_quoted_strings(runner, styled)


def style_quoted_strings(runner: Runner | None, text: str) -> str:
    """Apply `display/style.string` to single- or double-quoted spans."""
    if runner is None:
        return text
    style = runner.registry.varstore.get(DISPLAY_STRING_STYLE_VAR, "")
    if not style:
        return text
    parts: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char not in {"'", '"'}:
            parts.append(char)
            index += 1
            continue
        end = closing_quote_index(text, index)
        if end is None:
            parts.append(ansi_color(text[index:], style))
            break
        parts.append(ansi_color(text[index:end + 1], style))
        index = end + 1
    return "".join(parts)


def closing_quote_index(text: str, start: int) -> int | None:
    """Return the matching quote index, ignoring backslash-escaped quotes."""
    quote = text[start]
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index
        index += 1
    return None


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
