"""Traceroute commandlet.

Provides a Linux-testable network plugin that turns route tracing output into
normalized `network.route.hop` facts.

Consumes:
- `host.found` events from discovery.

Emits:
- `host.found` for the traced target, so downstream commandlets can continue
  working on the intended host.
- `network.route.hop` events, one per hop and target.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from bywaf.event_schema_objects import HostFound, NetworkRouteHop
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.plugin.process import ProcessResult
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

HOP_RE = re.compile(r"^\s*(?P<hop>\d+)(?:\?:|:)?\s+(?P<body>.+?)\s*$")
HOST_IP_RE = re.compile(r"^(?P<host>\S+)\s+\((?P<ip>[^)]+)\)")
RTT_RE = re.compile(r"(?P<rtt>\d+(?:\.\d+)?)\s*ms\b")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")


@commandlet
def traceroute(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Trace routes for explicit targets or upstream `host.found` events."""
    cfg = cast(TracerouteConfig, cfg)
    targets = trace_targets(cfg.targets, input_events)
    if not targets:
        raise ValueError("traceroute requires targets or host.found input")
    for target in targets:
        context.raise_if_cancelled()
        result = run_traceroute(context, cfg, target)
        if result is None:
            continue
        hops = parse_traceroute_output(target, result.stdout)
        context.output(render_trace_hops(context, target, hops))
        context.events.publish("host.found", HostFound(target, status="reachable", scanner="traceroute").to_payload())
        context.alert(f"traceroute found {len(hops)} hops for {target}", silent=cfg.silent)
        for hop in hops:
            yield hop.to_payload()


class TracerouteConfig(RunConfig):
    """Typed effective config for traceroute."""

    binary: str
    maxhops: int
    silent: bool
    targets: list[str]
    timeout: float


@dataclass(frozen=True, slots=True)
class TraceCommand:
    """Resolved traceroute command line for one target."""

    argv: tuple[str, ...]
    target: str


def trace_targets(targets: list[str], input_events: Iterable[Event]) -> list[str]:
    """Resolve trace targets from explicit args or upstream `host.found` events."""
    if targets:
        return list(dict.fromkeys(targets))
    resolved: list[str] = []
    for event in input_events:
        if event.topic != HostFound.__topic__:
            continue
        host = HostFound.from_event(event).host
        if host:
            resolved.append(host)
    return list(dict.fromkeys(resolved))


def run_traceroute(context: CommandContext, cfg: TracerouteConfig, target: str) -> ProcessResult | None:
    """Run traceroute through the framework process API and publish tool errors."""
    command = trace_command(cfg, target)
    try:
        result = context.process.run(command.argv, timeout=max(cfg.timeout * cfg.maxhops, cfg.timeout + 1))
    except OSError as exc:
        publish_trace_error(context, cfg.binary, target, str(exc))
        return None
    except Exception as exc:
        if exc.__class__.__name__ != "TimeoutExpired":
            raise
        publish_trace_error(context, cfg.binary, target, str(exc))
        return None
    if not result.ok and not result.stdout:
        publish_trace_error(context, cfg.binary, target, result.stderr.strip() or f"{cfg.binary} exited with {result.returncode}")
    return result


def publish_trace_error(context: CommandContext, tool: str, target: str, message: str) -> None:
    """Publish a traceroute tool error."""
    context.output(f"traceroute: {target}: {message}")
    context.events.publish(
        "tool.error",
        {
            "tool": tool,
            "severity": "error",
            "message": message,
            "target": target,
        },
    )


def render_trace_hops(context: CommandContext, target: str, hops: list[NetworkRouteHop]) -> str:
    """Render route hops for direct operator feedback."""
    if not hops:
        return f"Traceroute: {target}\nno route hops parsed"
    rows = [
        (
            hop.hop,
            hop.host or hop.status or "",
            hop.ip or "",
            format_rtt(hop.rtt_ms),
        )
        for hop in hops
    ]
    table = render_table(
        ("HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Traceroute: {target} ({len(hops)} hop{'s' if len(hops) != 1 else ''})\n{table}"


def format_rtt(value: float | None) -> str:
    """Format one traceroute round-trip time."""
    if value is None:
        return ""
    return f"{value:g} ms"


def trace_command(cfg: TracerouteConfig, target: str) -> TraceCommand:
    """Return the external traceroute argv for one target."""
    binary = cfg.binary or "traceroute"
    if binary.endswith("tracepath"):
        return TraceCommand((binary, "-m", str(cfg.maxhops), target), target)
    return TraceCommand((binary, "-m", str(cfg.maxhops), "-w", str(cfg.timeout), target), target)


def parse_traceroute_output(target: str, output: str) -> list[NetworkRouteHop]:
    """Parse common traceroute/tracepath output into route hop objects."""
    hops: list[NetworkRouteHop] = []
    for line in output.splitlines():
        hop = parse_traceroute_line(target, line)
        if hop is not None:
            hops.append(hop)
    return hops


def parse_traceroute_line(target: str, line: str) -> NetworkRouteHop | None:
    """Parse one traceroute result line."""
    match = HOP_RE.match(line)
    if not match:
        return None
    hop_number = int(match.group("hop"))
    body = match.group("body").strip()
    if not body or body.startswith("*"):
        return NetworkRouteHop(target, hop_number, status="timeout", scanner="traceroute")

    host = ""
    ip = ""
    host_ip = HOST_IP_RE.match(body)
    if host_ip:
        host = host_ip.group("host")
        ip = host_ip.group("ip")
    else:
        first = body.split()[0]
        if IP_RE.match(first):
            ip = first
            host = first
        else:
            host = first

    rtt_match = RTT_RE.search(body)
    rtt_ms = float(rtt_match.group("rtt")) if rtt_match else None
    return NetworkRouteHop(
        target,
        hop_number,
        host=host or None,
        ip=ip or None,
        rtt_ms=rtt_ms,
        status="responded",
        scanner="traceroute",
    )


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return traceroute
