"""TCP banner grabbing commandlet.

Provides a small Linux-testable network plugin that turns open TCP ports into
normalized `tcp.banner` facts.

Consumes:
- `port.open` events from port scanning.

Emits:
- `tcp.banner` for captured banners, first responses, or read/connect errors.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from bywaf.event_schema_objects import OpenPort, TcpBanner
from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    ManifestCommandlet,
    RunConfig,
)


class TcpBannerGrabber(ManifestCommandlet):
    def handle(
        self,
        context: CommandContext,
        cfg: RunConfig,
        input_events: Iterable[Event],
    ):
        """Grab banners for explicit targets or upstream `port.open` events."""
        cfg = cast(TcpBannerConfig, cfg)
        for target in banner_targets(cfg.targets, cfg.port, input_events):
            context.raise_if_cancelled()
            context.audit_capability("network.connect")
            result = grab_tcp_banner(target.host, target.port, cfg.timeout, cfg.read_bytes, cfg.mode)
            banner_text = str(result.get("banner") or "")
            error_text = str(result.get("error") or "")
            elapsed_value = result.get("elapsed_ms")
            banner = TcpBanner(
                target.host,
                target.port,
                banner=banner_text,
                error=error_text,
                elapsed_ms=elapsed_value if isinstance(elapsed_value, int) else None,
                scanner="tcp_banner",
            )
            payload = banner.to_payload()
            context.alert(
                banner_alert_text(target.host, target.port, payload),
                silent=cfg.silent,
            )
            yield payload


@dataclass(frozen=True, slots=True)
class BannerTarget:
    """One host/port pair to probe."""

    host: str
    port: int


class TcpBannerConfig(RunConfig):
    """Typed effective config for tcp_banner."""

    targets: list[str]
    mode: str
    port: int | None
    read_bytes: int
    silent: bool
    timeout: float


def banner_targets(targets: list[str], port: int | None, input_events: Iterable[Event]) -> list[BannerTarget]:
    """Resolve targets from explicit args or upstream `port.open` events."""
    if targets:
        return [target_from_text(target, port) for target in targets]
    resolved: list[BannerTarget] = []
    for event in input_events:
        if event.topic != OpenPort.__topic__:
            continue
        open_port = OpenPort.from_event(event)
        if open_port.protocol == "tcp":
            resolved.append(BannerTarget(open_port.host, open_port.port))
    return resolved


def target_from_text(target: str, default_port: int | None) -> BannerTarget:
    """Parse host[:port] text into a banner target."""
    if ":" in target and not target.startswith("["):
        host, port_text = target.rsplit(":", 1)
        return BannerTarget(host, int(port_text))
    if default_port is None:
        raise ValueError("tcp_banner explicit hosts require port= or host:port")
    return BannerTarget(target.strip("[]"), default_port)


def grab_tcp_banner(host: str, port: int, timeout: float, read_bytes: int, mode: str) -> dict[str, object]:
    """Connect to a TCP service and return a bounded first response."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = probe_bytes(mode, host)
            if probe:
                sock.sendall(probe)
            data = sock.recv(read_bytes)
    except OSError as exc:
        return {"error": str(exc), "elapsed_ms": elapsed_ms(start)}
    return {"banner": decode_banner(data), "elapsed_ms": elapsed_ms(start)}


def probe_bytes(mode: str, host: str) -> bytes:
    """Return bytes to send before reading for the selected mode."""
    if mode == "http-head":
        return f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")
    return b""


def decode_banner(data: bytes) -> str:
    """Decode and compact a bounded banner response."""
    return " ".join(data.decode("utf-8", errors="replace").replace("\x00", "").split())


def banner_alert_text(host: str, port: int, payload: dict[str, object]) -> str:
    """Return a concise operator alert for one banner result."""
    if payload.get("banner"):
        return f"captured banner from {host}:{port}/tcp"
    return f"no banner from {host}:{port}/tcp: {payload.get('error', 'empty response')}"


def elapsed_ms(start: float) -> int:
    """Return elapsed milliseconds from a monotonic start time."""
    return int((time.monotonic() - start) * 1000)


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return TcpBannerGrabber()
