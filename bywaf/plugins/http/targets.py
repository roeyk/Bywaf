"""Shared HTTP target normalization for bundled HTTP commandlets."""

from __future__ import annotations

import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.event import Event


@dataclass(frozen=True, slots=True)
class HttpTarget:
    """Normalized HTTP target derived from text or a `port.open` event.

    Constructed by: `http_targets()`, `http_target_from_text()`, and
    `http_target_from_port()`.
    Used by: bundled HTTP commandlets that need host, port, scheme, path, and
    display URL fields before making one request.
    """

    url: str
    host: str
    port: int
    scheme: str
    path: str


def http_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[HttpTarget]:
    """Resolve explicit HTTP targets or derive them from upstream port events.

    Called by: bundled HTTP commandlets such as `http_auth`, `http_methods`,
    and `http_cors` before applying scope policy and opening connections.
    """
    if targets:
        return [http_target_from_text(target, scheme, path) for target in targets]
    return [
        http_target_from_port(event, scheme, path)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]


def http_target_from_port(event: Event, scheme: str, path: str) -> HttpTarget:
    """Convert one `port.open` event into a normalized HTTP target."""
    host = str(event.payload["host"])
    port = int(event.payload["port"])
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return HttpTarget(
        build_url(selected_scheme, host, port, normalized_path),
        host,
        port,
        selected_scheme,
        normalized_path,
    )


def http_target_from_text(target: str, scheme: str, path: str) -> HttpTarget:
    """Parse URL, host, or host:port text into a normalized HTTP target."""
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        selected_scheme = parsed.scheme
        port = parsed.port or (443 if selected_scheme == "https" else 80)
        normalized_path = parsed.path or normalize_path(path)
        if parsed.query:
            normalized_path = f"{normalized_path}?{parsed.query}"
        return HttpTarget(target, parsed.hostname or "", port, selected_scheme, normalized_path)
    host, port = split_host_port(target)
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return HttpTarget(
        build_url(selected_scheme, host, port, normalized_path),
        host,
        port,
        selected_scheme,
        normalized_path,
    )


def split_host_port(target: str) -> tuple[str, int]:
    """Parse host[:port] text, defaulting to port 80."""
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 80


def choose_scheme(port: int, scheme: str) -> str:
    """Choose HTTP/HTTPS from a user override or common port convention."""
    if scheme != "auto":
        return scheme
    return "https" if port == 443 else "http"


def normalize_path(path: str) -> str:
    """Return a request path with a leading slash."""
    return path if path.startswith("/") else f"/{path}"


def build_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build a normalized URL, omitting default HTTP and HTTPS ports."""
    normalized_path = normalize_path(path)
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{normalized_path}"
