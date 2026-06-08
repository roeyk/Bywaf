"""HTTP method inspection commandlet."""

from __future__ import annotations

import http.client
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {"path": "/", "scheme": "auto", "silent": "false", "timeout": 5}
WRITE_METHODS = ("PUT", "PATCH", "DELETE")
WEBDAV_METHODS = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


@commandlet(
    name="http_methods",
    description="Probe HTTP OPTIONS and report risky allowed methods.",
    usage="http_methods [options] [target ...]",
    examples=(
        "http_methods https://example.test/",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_methods",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("silent", "suppress probe alerts", "false")
@option("timeout", "request timeout seconds", "5")
class HttpMethods(CommandletBase):
    """Probe OPTIONS and emit method posture facts plus candidates."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("--path", default=self.var_default(context, "path", "/"))
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default=self.var_default(context, "scheme", "auto"))
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parsed = parser.parse_args(args)
        targets = filter_targets_by_host(
            context,
            method_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            context.audit_capability("network.connect")
            result = probe_methods(target, timeout=parsed.timeout)
            payload = result_payload(target, result)
            for finding in method_findings(payload):
                context.events.publish("finding.candidate", finding)
            methods = methods_from_payload(payload)
            context.alert(
                f"observed HTTP methods {target.url} methods={','.join(methods) or 'unknown'}",
                silent=parsed.silent,
            )
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve explicit targets or derive targets from `port.open` events."""
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in method_targets(list(targets or []), input_events, scheme, path)
        ]


@dataclass(frozen=True, slots=True)
class MethodTarget:
    """Normalized HTTP target for OPTIONS probing."""

    url: str
    host: str
    port: int
    scheme: str
    path: str


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def method_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[MethodTarget]:
    """Resolve method-probe targets from arguments or upstream port events."""
    if targets:
        return [target_from_text(target, scheme, path) for target in targets]
    return [
        target_from_port_event(event, scheme, path)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]


def target_from_port_event(event: Event, scheme: str, path: str) -> MethodTarget:
    """Convert one `port.open` event into a method probe target."""
    host = str(event.payload["host"])
    port = int(event.payload["port"])
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return MethodTarget(build_url(selected_scheme, host, port, normalized_path), host, port, selected_scheme, normalized_path)


def target_from_text(target: str, scheme: str, path: str) -> MethodTarget:
    """Parse URL, host, or host:port text into a MethodTarget."""
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        selected_scheme = parsed.scheme
        port = parsed.port or (443 if selected_scheme == "https" else 80)
        normalized_path = parsed.path or normalize_path(path)
        if parsed.query:
            normalized_path = f"{normalized_path}?{parsed.query}"
        return MethodTarget(target, parsed.hostname or "", port, selected_scheme, normalized_path)
    host, port = split_host_port(target)
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return MethodTarget(build_url(selected_scheme, host, port, normalized_path), host, port, selected_scheme, normalized_path)


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


def normalize_path(path: str) -> str:
    """Return a request path with a leading slash."""
    return path if path.startswith("/") else f"/{path}"


def build_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build a normalized URL, omitting default ports."""
    normalized_path = normalize_path(path)
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{normalized_path}"


def probe_methods(target: MethodTarget, *, timeout: float) -> dict[str, object]:
    """Perform one OPTIONS request and return method metadata."""
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        connection.request("OPTIONS", target.path)
        response = connection.getresponse()
        allow = response.getheader("Allow") or ""
        public = response.getheader("Public") or ""
        methods = normalize_methods(allow or public)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "allow": allow,
            "public": public,
            "methods": methods,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"ok": False, "error": str(exc), "methods": []}
    finally:
        connection.close()


def normalize_methods(value: str) -> list[str]:
    """Return normalized HTTP method tokens from an Allow/Public header."""
    methods = {
        token.strip().upper()
        for token in value.replace(";", ",").split(",")
        if token.strip().isalpha()
    }
    return sorted(methods)


def result_payload(target: MethodTarget, result: dict[str, object]) -> dict[str, object]:
    """Return the plugin-owned `http.methods` fact payload."""
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "status": result.get("status"),
        "methods": result.get("methods", []),
        "allow": result.get("allow", ""),
        "public": result.get("public", ""),
        "error": result.get("error", ""),
    }


def method_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote risky allowed methods into normalized finding candidates."""
    methods = methods_from_payload(payload)
    findings: list[dict[str, object]] = []
    if "TRACE" in methods:
        findings.append(
            candidate_payload(
                title="HTTP TRACE method enabled",
                finding_class="web.method.trace_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-16"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed HTTP methods: {', '.join(methods)}.",
                recommendation="Disable TRACE unless there is a documented operational requirement.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    write_methods = [method for method in WRITE_METHODS if method in methods]
    if write_methods:
        findings.append(
            candidate_payload(
                title="HTTP write-capable methods enabled",
                finding_class="web.method.write_methods_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A01:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed write-capable HTTP methods: {', '.join(write_methods)}.",
                recommendation="Disable PUT, PATCH, and DELETE unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    webdav_methods = [method for method in WEBDAV_METHODS if method in methods]
    if webdav_methods:
        findings.append(
            candidate_payload(
                title="WebDAV HTTP methods enabled",
                finding_class="web.method.webdav_enabled",
                severity="medium",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed WebDAV HTTP methods: {', '.join(webdav_methods)}.",
                recommendation="Disable WebDAV methods unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    return findings


def methods_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return normalized method names from a loose event payload."""
    value = payload.get("methods", ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(method).upper() for method in value if method)


def target_payload(payload: dict[str, object]) -> dict[str, str]:
    """Return normalized target details for finding candidates."""
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return HttpMethods()
