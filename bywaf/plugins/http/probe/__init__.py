"""HTTP probing commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for HTTP
endpoint probing.

Consumes:
- `port.open` events or explicit URL/host command arguments.

Emits:
- `http.endpoint` for reachable HTTP services.
- `http.response` for response metadata.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.event import Event
from bywaf.event.schema_objects import HttpEndpoint
from bywaf.plugins.http.cookies import load_cookie_jar
from bywaf.plugins.http.targets import (
    HttpTarget,
    build_url as build_url,
    choose_scheme as choose_scheme,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
)
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {
    "cookie-file": "",
    "firefox-profile": "",
    "follow-redirects": "true",
    "method": "HEAD",
    "path": "/",
    "scheme": "auto",
    "silent": "false",
    "targets": "",
    "timeout": 5,
    "user-agent": "Bywaf/0.9",
}


@commandlet(
    name="http_probe",
    description="Probe HTTP/HTTPS endpoints and emit response metadata.",
    usage="http_probe [options] [target ...]",
    examples=(
        "http_probe https://example.test/",
        "set http/http_probe.cookie-file=/tmp/cookies.txt",
        "hostscanner 127.0.0.1 | portscanner | http_probe --method GET",
    ),
)
@option("cookie-file", "Netscape-format cookie file")
@option("firefox-profile", "Firefox profile directory or cookies.sqlite")
@option("follow-redirects", "follow redirects", "true", ("true", "false"))
@option("method", "HTTP method", "HEAD", ("HEAD", "GET"))
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("silent", "suppress probe alerts", "false")
@option("timeout", "request timeout seconds", "5")
@option("user-agent", "HTTP User-Agent", "Bywaf/0.9")
class HttpProbe(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--cookie-file", default=self.var_default(context, "cookie-file", None))
        parser.add_argument("--firefox-profile", default=self.var_default(context, "firefox-profile", None))
        parser.add_argument("--follow-redirects", choices=("true", "false"), default=self.var_default(context, "follow-redirects", "true"))
        parser.add_argument("--method", choices=("HEAD", "GET"), default=self.var_default(context, "method", "HEAD"))
        parser.add_argument("--path", default=self.var_default(context, "path", "/"))
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default=self.var_default(context, "scheme", "auto"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parser.add_argument("--user-agent", default=self.var_default(context, "user-agent", "Bywaf/0.9"))
        parsed = parser.parse_args(args)
        remember_option(context, "cookie-file", parsed.cookie_file)
        remember_option(context, "firefox-profile", parsed.firefox_profile)
        if parsed.cookie_file or parsed.firefox_profile:
            context.audit_capability("filesystem.read")
        # Build one opener per invocation so cookies and redirect policy apply
        # consistently across all explicit and pipeline-derived targets.
        opener = build_opener(parsed.cookie_file, parsed.firefox_profile, parsed.follow_redirects == "true")
        targets = self.values_or_var(context, parsed.targets, "targets")
        selected_targets = filter_targets_by_host(
            context,
            probe_targets(targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in selected_targets:
            context.audit_capability("network.connect")
            result = probe_url(opener, target.url, parsed.method, parsed.timeout, parsed.user_agent)
            endpoint = HttpEndpoint(
                target.url,
                target.host,
                target.port,
                target.scheme,
                status=result.get("status"),
                method=parsed.method,
                server=result.get("server", ""),
                error=result.get("error", ""),
            )
            payload = {**endpoint.to_payload(), **result}
            context.alert(
                f"discovered HTTP endpoint {target.url} status={payload.get('status')}",
                silent=parsed.silent,
            )
            yield payload


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """Normalized HTTP target derived from text or a `port.open` event."""

    url: str
    host: str
    port: int
    scheme: str


def build_opener(cookie_file: str | None, firefox_profile: str | None, follow_redirects: bool):
    """Build a urllib opener with optional cookies and redirect policy."""
    handlers = []
    if cookie_file or firefox_profile:
        handlers.append(urllib.request.HTTPCookieProcessor(load_cookie_jar(cookie_file, firefox_profile)))
    if not follow_redirects:
        handlers.append(NoRedirectHandler())
    return urllib.request.build_opener(*handlers)


def remember_option(context: CommandContext, name: str, explicit: str | None) -> None:
    """Persist explicitly supplied options into the session varstore."""
    if explicit:
        # Cookie/profile settings are often reused across several HTTP tools, so
        # an explicit value becomes the commandlet-scoped default for later runs.
        context.vars.set(name, explicit)


def probe_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[ProbeTarget]:
    """Resolve probe targets from args or upstream `port.open` events."""
    return [_probe_target(target) for target in http_targets(targets, input_events, scheme, path)]


def target_from_port_event(event: Event, scheme: str, path: str) -> ProbeTarget:
    """Convert one `port.open` event into an HTTP probe target."""
    return _probe_target(http_target_from_port_event(event, scheme, path))


def target_from_text(target: str, scheme: str, path: str) -> ProbeTarget:
    """Parse URL, host, or host:port text into a ProbeTarget."""
    return _probe_target(http_target_from_text(target, scheme, path))


def _probe_target(target: HttpTarget) -> ProbeTarget:
    """Adapt the shared HTTP target model to http_probe's legacy target shape."""
    return ProbeTarget(target.url, target.host, target.port, target.scheme)


def probe_url(opener, url: str, method: str, timeout: float, user_agent: str) -> dict:
    """Perform one HTTP request and return success or error metadata."""
    request = urllib.request.Request(url, method=method, headers={"User-Agent": user_agent})
    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            # For GET requests we keep only a bounded body sample. It is enough
            # for title/fingerprint extraction and avoids storing full pages.
            body = response.read(65536) if method == "GET" else b""
            return response_payload(response, body, time.monotonic() - start)
    except urllib.error.HTTPError as exc:
        body = exc.read(65536) if method == "GET" else b""
        return response_payload(exc, body, time.monotonic() - start)
    except urllib.error.URLError as exc:
        return {"ok": False, "error": str(exc.reason), "elapsed_ms": int((time.monotonic() - start) * 1000)}


def response_payload(response, body: bytes, elapsed: float) -> dict:
    """Extract stable response fields from urllib response-like objects."""
    headers = dict(response.headers)
    return {
        "ok": True,
        "status": response.status,
        "reason": response.reason,
        "final_url": response.geturl(),
        "elapsed_ms": int(elapsed * 1000),
        "headers": headers,
        "server": headers.get("Server", ""),
        "content_type": headers.get("Content-Type", ""),
        "location": headers.get("Location", ""),
        "title": extract_title(body),
    }


def extract_title(body: bytes) -> str:
    """Extract and normalize an HTML title from a bounded response body."""
    if not body:
        return ""
    match = re.search(rb"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1).decode("utf-8", errors="replace")).strip()


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Tell urllib not to follow redirects by returning None."""
        return None


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HttpProbe()
