"""HTTP path probing commandlet."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import cast

from bywaf.event.schema_objects import HttpEndpoint, HttpPathObserved
from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet, split_var_values
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULT_PATHS = "/robots.txt,/.git/config,/server-status,/admin/,/login,/wp-login.php,/.env,/actuator/env"
ADMIN_PATHS = frozenset({"/admin/", "/admin", "/login", "/wp-login.php"})
ADMIN_KEYWORDS = ("admin", "administrator", "login", "sign in", "wp-login")


@commandlet
def http_paths(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Probe common HTTP paths from explicit bases or upstream endpoints."""
    cfg = cast(HttpPathsConfig, cfg)
    for base in filter_targets_by_host(context, base_urls(cfg.targets, input_events), host_from_url):
        for path in split_var_values(cfg.paths):
            context.raise_if_cancelled()
            url = join_url(base, path)
            context.audit_capability("network.connect")
            result = probe_path(url, cfg.timeout, cfg.user_agent)
            raw_status = result.get("status")
            raw_length = result.get("length")
            observed = HttpPathObserved(
                url=url,
                host=urllib.parse.urlparse(url).hostname or "",
                port=urllib.parse.urlparse(url).port or default_port(url),
                path=urllib.parse.urlparse(url).path or "/",
                status=raw_status if isinstance(raw_status, int) else None,
                title=str(result.get("title") or ""),
                content_type=str(result.get("content_type") or ""),
                length=raw_length if isinstance(raw_length, int) else None,
                interesting=is_interesting_path(path, result),
                scanner="http_paths",
            )
            context.events.publish("http.path", observed.to_payload())
            finding = finding_for_path(observed)
            if finding:
                context.events.publish("finding.candidate", finding)
            context.alert(f"checked {url} status={observed.status}", silent=cfg.silent)
    return ()


class HttpPathsConfig(RunConfig):
    """Typed effective config for http_paths."""

    targets: list[str]
    paths: str
    silent: bool
    timeout: float
    user_agent: str


def base_urls(targets: list[str], input_events: Iterable[Event]) -> list[str]:
    """Return base URLs from explicit args or upstream HTTP endpoints."""
    if targets:
        return [normalize_base_url(target) for target in targets]
    urls: list[str] = []
    for event in input_events:
        if event.topic == HttpEndpoint.__topic__:
            endpoint = HttpEndpoint.from_event(event)
            parsed = urllib.parse.urlparse(endpoint.url)
            urls.append(f"{parsed.scheme}://{parsed.netloc}/")
    return list(dict.fromkeys(urls))


def host_from_url(url: str) -> str:
    """Return the network host portion of a URL."""
    return urllib.parse.urlparse(url).hostname or ""


def normalize_base_url(value: str) -> str:
    """Normalize host or URL text into an HTTP base URL."""
    if value.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(value)
        return f"{parsed.scheme}://{parsed.netloc}/"
    return f"http://{value.strip('/')}/"


def join_url(base: str, path: str) -> str:
    """Join one base URL with one absolute or relative path."""
    return urllib.parse.urljoin(base, path if path.startswith("/") else f"/{path}")


def default_port(url: str) -> int:
    """Return default port for a URL."""
    return 443 if urllib.parse.urlparse(url).scheme == "https" else 80


def probe_path(url: str, timeout: float, user_agent: str) -> dict[str, object]:
    """Fetch a path and return bounded response metadata."""
    if not is_http_url(url):
        return {"error": "unsupported URL scheme"}
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": user_agent})
    try:
        # URL scheme is restricted to HTTP(S) above.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            body = response.read(65536)
            return response_metadata(response, body)
    except urllib.error.HTTPError as exc:
        body = exc.read(65536)
        return response_metadata(exc, body)
    except urllib.error.URLError as exc:
        return {"error": str(exc.reason)}


def response_metadata(response, body: bytes) -> dict[str, object]:
    """Extract stable path response metadata."""
    text = body.decode("utf-8", errors="ignore")
    return {
        "status": response.status,
        "content_type": response.headers.get("Content-Type", ""),
        "length": len(body),
        "title": extract_title(text),
        "sample": text[:4096],
    }


def is_http_url(url: str) -> bool:
    """Return whether URL uses an HTTP transport scheme."""
    return urllib.parse.urlparse(url).scheme in {"http", "https"}


def extract_title(text: str) -> str:
    """Return a compact HTML title when present."""
    lowered = text.casefold()
    start = lowered.find("<title>")
    end = lowered.find("</title>", start + 7)
    if start == -1 or end == -1:
        return ""
    return " ".join(text[start + 7:end].split())


def is_interesting_path(path: str, result: dict[str, object]) -> bool:
    """Return whether a response should be highlighted."""
    status = result.get("status")
    if not isinstance(status, int) or status >= 400:
        return False
    lowered = path.casefold()
    sample = str(result.get("sample") or "").casefold()
    title = str(result.get("title") or "").casefold()
    return (
        lowered in {"/.git/config", "/server-status", "/.env", "/actuator/env"}
        or (lowered in ADMIN_PATHS and looks_like_admin_surface(title, sample))
        or "repositoryformatversion" in sample
        or "spring.cloud" in sample
        or "database_url" in sample
    )


def looks_like_admin_surface(title: str, sample: str) -> bool:
    """Return whether response text looks like a login or admin surface."""
    evidence = f"{title} {sample}"
    return any(keyword in evidence for keyword in ADMIN_KEYWORDS)


def finding_for_path(observed: HttpPathObserved) -> dict[str, object] | None:
    """Promote clearly risky HTTP path observations to finding candidates."""
    if not observed.interesting:
        return None
    if observed.path == "/.git/config":
        title = "Exposed Git repository configuration"
        finding_class = "web.repo.git_config_exposed"
        severity = "high"
    elif observed.path == "/server-status":
        title = "Exposed Apache server-status endpoint"
        finding_class = "web.server_status.exposed"
        severity = "medium"
    elif observed.path == "/.env":
        title = "Exposed environment configuration file"
        finding_class = "web.config.env_exposed"
        severity = "high"
    elif observed.path == "/actuator/env":
        title = "Exposed Spring Boot environment endpoint"
        finding_class = "web.spring.actuator_env_exposed"
        severity = "high"
    elif observed.path.casefold() in ADMIN_PATHS:
        title = "Exposed administrative login surface"
        finding_class = "web.admin_interface.exposed"
        severity = "low"
    else:
        title = f"Interesting HTTP path exposed: {observed.path}"
        finding_class = "web.path.interesting"
        severity = "low"
    return candidate_payload(
        title=title,
        finding_class=finding_class,
        severity=severity,
        target={"url": observed.url, "host": observed.host, "path": observed.path},
        target_scope={"kind": "web_route", "value": observed.url},
        affected=[{"url": observed.url, "host": observed.host}],
        evidence=f"{observed.url} returned HTTP {observed.status}",
        source={"tool": "http_paths", "topic": "http.path"},
    )


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return http_paths
