"""HTTP endpoint probe commandlet."""

from __future__ import annotations

import argparse
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.events import Event
from bywaf.http_cookies import load_cookie_jar
from bywaf.plugin import CommandContext, CommandSpec, Commandlet, OptionSpec, emit_alert

DEFAULTS = {
    "cookie-file": "",
    "firefox-profile": "",
    "method": "HEAD",
    "path": "/",
    "timeout": 5,
    "user-agent": "Bywaf/0.1",
}


class HttpProbe:
    spec = CommandSpec(
        name="http_probe",
        description="Probe HTTP/HTTPS endpoints and emit response metadata.",
        usage="http_probe [options] [target ...]",
        examples=(
            "http_probe https://example.test/",
            "vars http_probe.cookie-file=/tmp/cookies.txt",
            "hostscanner 127.0.0.1 | portscanner | http_probe --method GET",
        ),
        options=(
            OptionSpec("cookie-file", "Netscape-format cookie file"),
            OptionSpec("firefox-profile", "Firefox profile directory or cookies.sqlite"),
            OptionSpec("follow-redirects", "follow redirects", "true", ("true", "false")),
            OptionSpec("method", "HTTP method", "HEAD", ("HEAD", "GET")),
            OptionSpec("path", "request path", "/"),
            OptionSpec("scheme", "scheme override", "auto", ("auto", "http", "https")),
            OptionSpec("silent", "suppress probe alerts", "false"),
            OptionSpec("timeout", "request timeout seconds", "5"),
            OptionSpec("user-agent", "HTTP User-Agent", "Bywaf/0.1"),
        ),
        consumes=("port.open",),
        emits=("http.endpoint",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports."""
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true")
        parser.add_argument("--cookie-file")
        parser.add_argument("--firefox-profile")
        parser.add_argument("--follow-redirects", choices=("true", "false"), default="true")
        parser.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
        parser.add_argument("--path", default="/")
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default="auto")
        parser.add_argument("--timeout", type=float, default=5)
        parser.add_argument("--user-agent", default="Bywaf/0.1")
        parsed = parser.parse_args(args)
        cookie_file = option_or_var(context, "cookie-file", parsed.cookie_file)
        firefox_profile = option_or_var(context, "firefox-profile", parsed.firefox_profile)
        remember_option(context, "cookie-file", parsed.cookie_file)
        remember_option(context, "firefox-profile", parsed.firefox_profile)
        opener = build_opener(cookie_file, firefox_profile, parsed.follow_redirects == "true")
        for target in probe_targets(parsed.targets, input_events, parsed.scheme, parsed.path):
            result = probe_url(opener, target.url, parsed.method, parsed.timeout, parsed.user_agent)
            payload = {
                "url": target.url,
                "host": target.host,
                "port": target.port,
                "scheme": target.scheme,
                **result,
            }
            emit_alert(
                context,
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


def option_or_var(context: CommandContext, name: str, explicit: str | None) -> str | None:
    """Prefer a CLI option, then fall back to the plugin variable namespace."""
    if explicit:
        return explicit
    return context.vars.get(name) or None


def remember_option(context: CommandContext, name: str, explicit: str | None) -> None:
    """Persist explicitly supplied options into the session varstore."""
    if explicit:
        context.vars.set(name, explicit)


def probe_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[ProbeTarget]:
    """Resolve probe targets from args or upstream `port.open` events."""
    if targets:
        return [target_from_text(target, scheme, path) for target in targets]
    return [
        target_from_port_event(event, scheme, path)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]


def target_from_port_event(event: Event, scheme: str, path: str) -> ProbeTarget:
    """Convert one `port.open` event into an HTTP probe target."""
    host = str(event.payload["host"])
    port = int(event.payload["port"])
    selected_scheme = choose_scheme(port, scheme)
    return ProbeTarget(build_url(selected_scheme, host, port, path), host, port, selected_scheme)


def target_from_text(target: str, scheme: str, path: str) -> ProbeTarget:
    """Parse URL, host, or host:port text into a ProbeTarget."""
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        selected_scheme = parsed.scheme
        port = parsed.port or (443 if selected_scheme == "https" else 80)
        return ProbeTarget(target, parsed.hostname or "", port, selected_scheme)
    host, port = split_host_port(target)
    selected_scheme = choose_scheme(port, scheme)
    return ProbeTarget(build_url(selected_scheme, host, port, path), host, port, selected_scheme)


def split_host_port(target: str) -> tuple[str, int]:
    """Parse host[:port], defaulting to port 80."""
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 80


def choose_scheme(port: int, scheme: str) -> str:
    """Choose HTTP/HTTPS from a user override or common port convention."""
    if scheme != "auto":
        return scheme
    return "https" if port == 443 else "http"


def build_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build a normalized URL, omitting default ports."""
    normalized_path = path if path.startswith("/") else f"/{path}"
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{normalized_path}"


def probe_url(opener, url: str, method: str, timeout: float, user_agent: str) -> dict:
    """Perform one HTTP request and return success or error metadata."""
    request = urllib.request.Request(url, method=method, headers={"User-Agent": user_agent})
    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
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
