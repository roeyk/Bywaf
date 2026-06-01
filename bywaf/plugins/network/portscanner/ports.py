"""Open-port result view for the portscanner provider.

Provides a pentester-oriented view over `port.open` events.  The raw event log
remains available for audit work, while this command answers the common
operator question: "what did the latest port scan find?"

Used by:
- network.portscanner provider: exposes the companion `ports` view commandlet.
- REPL operators: inspect latest or selected portscanner results."""

from __future__ import annotations

import ipaddress
from argparse import Namespace
from collections.abc import Iterable

from bywaf.event.filters import filter_events_by_payload, parse_payload_filter_tokens
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.runtime.inventory_scope import events_new_to_scope
from bywaf.plugins.runtime.job import require_job
from bywaf.runtime_display import (
    command_context_style_getter,
    parse_runtime_sort,
    render_table,
    runtime_sort_completion_candidates,
    runtime_sort_key,
    runtime_sort_note,
    runtime_sort_reverse,
    terminal_table_width,
)

PORT_SORT_KEYS = ("host", "port", "protocol", "service", "reason", "event", "time")
PORT_FILTER_KEYS = {"host", "port", "protocol", "service", "reason", "state"}
PORT_SCOPE_KEYS = {"all", "job", "pipeline", "step"}


@commandlet(
    name="ports",
    description="Show open ports from the latest or selected port scan.",
    usage="ports [--last|--new] [job=latest|<id>] [pipeline=<id>] [step=<id>] [host=<selector>] [port=<selector>] [sort=<key>] [all=true]",
    examples=(
        "ports",
        "ports --last",
        "ports --new",
        "ports job=latest",
        "ports job=69 sort=host",
        "ports host=192.168.50.0/24,!192.168.50.1-128 port=80,443",
    ),
    consumes=("port.open",),
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Ports(CommandletBase):
    """Render a compact table of open-port discoveries."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse selectors, select port events, and print a result table."""
        del input_events
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("--last", action="store_true")
        parser.add_argument("--new", action="store_true")
        parser.add_argument("--page", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        selectors = parse_ports_selectors(tokens, last=parsed.last, new=parsed.new)
        context.require_foreground("port result views")
        events = select_port_events(context, selectors)
        events = filter_events_by_payload(events, selectors.filters)
        if not events:
            context.output(no_ports_message(selectors))
            return ()
        output = render_ports(context, events, selectors)
        if parsed.page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete selectors and sort keys."""
        del context
        candidates = [
            "--page",
            "--last",
            "--new",
            "all=true",
            "job=",
            "job=latest",
            "pipeline=",
            "step=",
            "host=",
            "port=",
            "protocol=",
            "service=",
            "reason=",
            "sort=",
        ]
        if args and args[-1].startswith("sort="):
            return runtime_sort_completion_candidates(args[-1], PORT_SORT_KEYS)
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_ports_selectors(tokens: list[str], *, last: bool = False, new: bool = False) -> Namespace:
    """Parse `ports` selector tokens into scope, filters, and sort order."""
    scope: dict[str, str] = {}
    filters: list[str] = []
    sort_key = "host"
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"ports uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("ports selectors must be key=value")
        if key == "sort":
            sort_key = parse_runtime_sort(value, PORT_SORT_KEYS, "ports")
        elif key in PORT_SCOPE_KEYS:
            scope[key] = value
        elif key in PORT_FILTER_KEYS:
            filters.append(token)
        else:
            raise ValueError(
                "ports selectors must be one of: all, job, pipeline, step, host, port, protocol, service, reason, state, sort"
            )
    validate_ports_scope(scope)
    if last and new:
        raise ValueError("ports accepts only one of --last or --new")
    if (last or new) and scope.get("all") == "true":
        raise ValueError("ports all=true cannot be combined with --last or --new")
    return Namespace(scope=scope, filters=parse_payload_filter_tokens(filters), sort=sort_key, last=last, new=new)


def validate_ports_scope(scope: dict[str, str]) -> None:
    """Reject ambiguous scope combinations."""
    all_value = scope.get("all", "false")
    if all_value not in {"true", "false"}:
        raise ValueError("ports all= must be true or false")
    explicit_scopes = [key for key in ("job", "pipeline", "step") if key in scope]
    if all_value == "true" and explicit_scopes:
        raise ValueError("ports all=true cannot be combined with job=, pipeline=, or step=")
    if len(explicit_scopes) > 1:
        raise ValueError("ports accepts only one runtime scope: job=, pipeline=, or step=")


def select_port_events(context: CommandContext, selectors: Namespace) -> list[Event]:
    """Select raw port events from the requested scope.

    With no explicit scope, use the latest portscanner run that actually emitted
    `port.open`.  That mirrors how operators consult an nmap result file after a
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
        return [event for event in events.events_for_job(row["id"], limit=10000) if event.topic == "port.open"]
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


def sort_port_events(events: list[Event], sort_key: str) -> list[Event]:
    """Sort port rows by the requested operator-facing column."""
    display_key = runtime_sort_key(sort_key)
    reverse = runtime_sort_reverse(sort_key)
    if display_key in {"event", "time"}:
        return sorted(events, key=lambda event: event.id or 0, reverse=reverse)
    return sorted(events, key=lambda event: port_sort_value(event, display_key), reverse=reverse)


def port_sort_value(event: Event, sort_key: str) -> tuple[object, ...]:
    """Return stable sort values for port rows."""
    payload = event.payload
    if sort_key == "host":
        return (ip_sort_value(payload.get("host")), int(payload.get("port") or 0), event.id or 0)
    if sort_key == "port":
        return (int(payload.get("port") or 0), str(payload.get("host") or ""), event.id or 0)
    return (str(payload.get(sort_key) or ""), str(payload.get("host") or ""), int(payload.get("port") or 0), event.id or 0)


def ip_sort_value(value: object) -> tuple[int, bytes | str]:
    """Sort IP addresses numerically and fall back to text for host names."""
    text = str(value or "")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return (99, text)
    return (address.version, address.packed)


def render_ports(context: CommandContext, events: list[Event], selectors: Namespace) -> str:
    """Render the selected open ports as a compact table."""
    scope = ports_scope_label(context, selectors)
    table = render_ports_table(context, events, selectors.sort)
    heading = f"Ports: {scope} ({len(events)} open port{'s' if len(events) != 1 else ''})"
    if runtime_sort_key(selectors.sort) in {"host", "port"}:
        return f"{heading}\n{runtime_sort_note(selectors.sort, label='grouped by')}\n{table}"
    return f"{heading}\n{runtime_sort_note(selectors.sort)}\n{table}"


def render_ports_table(context: CommandContext, events: list[Event], sort_key: str) -> str:
    """Render either grouped scan results or raw event rows."""
    display_key = runtime_sort_key(sort_key)
    reverse = runtime_sort_reverse(sort_key)
    if display_key == "host":
        return render_ports_by_host(context, events, reverse=reverse)
    if display_key == "port":
        return render_ports_by_port(context, events, reverse=reverse)
    sorted_events = sort_port_events(events, sort_key)
    rows = [raw_port_row(event) for event in sorted_events]
    return render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "REASON", "EVENT"),
        rows,
        cell_subjects=("host", "port", "protocol", "service", "", "event"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_ports_by_host(context: CommandContext, events: list[Event], *, reverse: bool = False) -> str:
    """Render one host row with all ports discovered on that host."""
    grouped: dict[str, list[Event]] = {}
    for event in events:
        grouped.setdefault(str(event.payload.get("host", "")), []).append(event)
    rows = [
        (
            host,
            ", ".join(dict.fromkeys(port_endpoint_text(event) for event in sort_port_events(grouped[host], "port"))),
        )
        for host in sorted(grouped, key=ip_sort_value, reverse=reverse)
    ]
    return render_table(
        ("HOST", "OPEN PORTS"),
        rows,
        cell_subjects=("host", "port"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_ports_by_port(context: CommandContext, events: list[Event], *, reverse: bool = False) -> str:
    """Render one port row with all hosts exposing that port."""
    grouped: dict[tuple[int, str, str], list[Event]] = {}
    for event in events:
        payload = event.payload
        grouped.setdefault(
            (
                int(payload.get("port") or 0),
                str(payload.get("protocol") or ""),
                str(payload.get("service") or ""),
            ),
            [],
        ).append(event)
    rows = [
        (
            port,
            protocol,
            service,
            ", ".join(sorted(hosts_for_events(grouped[key]), key=ip_sort_value)),
        )
        for key, port, protocol, service in (
            (key, key[0], key[1], key[2])
            for key in sorted(grouped, key=lambda item: (item[0], item[1], item[2]), reverse=reverse)
        )
    ]
    return render_table(
        ("PORT", "PROTO", "SERVICE", "HOSTS"),
        rows,
        cell_subjects=("port", "protocol", "service", "host"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def raw_port_row(event: Event) -> tuple[object, ...]:
    """Return a one-event table row."""
    return (
        event.payload.get("host", ""),
        event.payload.get("port", ""),
        event.payload.get("protocol", ""),
        event.payload.get("service", ""),
        event.payload.get("reason", ""),
        event.id,
    )


def port_endpoint_text(event: Event) -> str:
    """Return compact `port/proto service` text for grouped host rows."""
    payload = event.payload
    endpoint = f"{payload.get('port', '')}/{payload.get('protocol', '')}".rstrip("/")
    service = str(payload.get("service") or "")
    return f"{endpoint} {service}".strip()


def hosts_for_events(events: list[Event]) -> set[str]:
    """Return unique hosts from a group of port events."""
    return {str(event.payload.get("host", "")) for event in events if event.payload.get("host") is not None}


def ports_scope_label(context: CommandContext, selectors: Namespace) -> str:
    """Return a short human-readable scope description."""
    scope = selectors.scope
    if getattr(selectors, "new", False):
        prefix = "new in "
    elif getattr(selectors, "last", False):
        prefix = "latest "
    else:
        prefix = ""
    if scope.get("all") == "true":
        return "all port.open events"
    if scope.get("job") == "latest" or (not scope and not getattr(selectors, "new", False)):
        latest = latest_portscanner_scope(context)
        if latest is not None and latest.job_id:
            return f"latest portscanner job={latest.job_id}"
        return "latest portscanner scan"
    if getattr(selectors, "new", False) and not scope:
        return "new since prior port inventory"
    if "job" in scope:
        return f"{prefix}job={scope['job']}"
    if "pipeline" in scope:
        return f"{prefix}pipeline={scope['pipeline']}"
    if "step" in scope:
        return f"{prefix}step={scope['step']}"
    return "selected port.open events"


def no_ports_message(selectors: Namespace) -> str:
    """Return the empty-result message for the selected scope."""
    if selectors.scope:
        return "no port.open events for selected scope"
    return "no port scan results"


def plugin() -> Commandlet:
    """Return the runtime ports commandlet."""
    return Ports()
