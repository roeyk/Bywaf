"""HTTP authentication challenge posture commandlet."""

from __future__ import annotations

import http.client
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {"path": "/", "scheme": "auto", "method": "HEAD", "timeout": 5}
ADMIN_PATH_HINTS = ("/admin", "/login", "/manager", "/console", "/dashboard", "/wp-admin")


@commandlet(
    name="http_auth",
    description="Probe HTTP auth challenges and report passive auth posture findings.",
    usage="http_auth [options] [target ...]",
    examples=(
        "http_auth https://example.test/admin",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_auth path=/admin",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("method", "HTTP method", "HEAD", ("HEAD", "GET"))
@option("timeout", "request timeout seconds", "5")
class HttpAuth(CommandletBase):
    """Probe one request and emit HTTP authentication posture facts."""

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
        parser.add_argument("--method", choices=("HEAD", "GET"), default=self.var_default(context, "method", "HEAD"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parsed = parser.parse_args(args)
        targets = filter_targets_by_host(
            context,
            auth_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            context.audit_capability("network.connect")
            result = probe_auth(target, method=parsed.method, timeout=parsed.timeout)
            payload = result_payload(target, result, parsed.method)
            for finding in auth_findings(payload):
                context.events.publish("finding.candidate", finding)
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve explicit targets or derive targets from `port.open` events."""
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in auth_targets(list(targets or []), input_events, scheme, path)
        ]


@dataclass(frozen=True, slots=True)
class AuthTarget:
    """Normalized HTTP target for auth challenge probing."""

    url: str
    host: str
    port: int
    scheme: str
    path: str


def auth_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[AuthTarget]:
    """Resolve auth-probe targets from arguments or upstream port events."""
    if targets:
        return [target_from_text(target, scheme, path) for target in targets]
    return [
        target_from_port_event(event, scheme, path)
        for event in input_events
        if "host" in event.payload and "port" in event.payload
    ]


def target_from_port_event(event: Event, scheme: str, path: str) -> AuthTarget:
    """Convert one `port.open` event into an auth probe target."""
    host = str(event.payload["host"])
    port = int(event.payload["port"])
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return AuthTarget(build_url(selected_scheme, host, port, normalized_path), host, port, selected_scheme, normalized_path)


def target_from_text(target: str, scheme: str, path: str) -> AuthTarget:
    """Parse URL, host, or host:port text into an AuthTarget."""
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        selected_scheme = parsed.scheme
        port = parsed.port or (443 if selected_scheme == "https" else 80)
        normalized_path = parsed.path or normalize_path(path)
        if parsed.query:
            normalized_path = f"{normalized_path}?{parsed.query}"
        return AuthTarget(target, parsed.hostname or "", port, selected_scheme, normalized_path)
    host, port = split_host_port(target)
    selected_scheme = choose_scheme(port, scheme)
    normalized_path = normalize_path(path)
    return AuthTarget(build_url(selected_scheme, host, port, normalized_path), host, port, selected_scheme, normalized_path)


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


def probe_auth(target: AuthTarget, *, method: str, timeout: float) -> dict[str, object]:
    """Perform one HTTP request and return auth challenge metadata."""
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        connection.request(method, target.path)
        response = connection.getresponse()
        challenges = response.getheaders()
        www_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "www-authenticate" and value.strip()
        ]
        proxy_authenticate = [
            value
            for name, value in challenges
            if name.lower() == "proxy-authenticate" and value.strip()
        ]
        schemes = normalize_schemes(www_authenticate + proxy_authenticate)
        realms = challenge_realms(www_authenticate + proxy_authenticate)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "www_authenticate": www_authenticate,
            "proxy_authenticate": proxy_authenticate,
            "schemes": schemes,
            "realms": realms,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"ok": False, "error": str(exc), "schemes": [], "realms": []}
    finally:
        connection.close()


def normalize_schemes(challenges: list[str]) -> list[str]:
    """Return normalized authentication scheme tokens from challenge headers."""
    schemes = []
    for challenge in challenges:
        token = challenge.strip().split(None, 1)[0].strip(",")
        if token and token.replace("-", "").isalnum():
            schemes.append(token.upper())
    return sorted(set(schemes))


def challenge_realms(challenges: list[str]) -> list[str]:
    """Return realm values from simple WWW-Authenticate challenge headers."""
    realms = []
    for challenge in challenges:
        lowered = challenge.lower()
        marker = 'realm="'
        start = lowered.find(marker)
        if start == -1:
            continue
        start += len(marker)
        end = challenge.find('"', start)
        if end != -1:
            realms.append(challenge[start:end])
    return sorted(set(realms))


def result_payload(target: AuthTarget, result: dict[str, object], method: str) -> dict[str, object]:
    """Return the plugin-owned `http.auth` fact payload."""
    schemes = result.get("schemes", [])
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "method": method,
        "status": result.get("status"),
        "auth_present": bool(schemes),
        "schemes": schemes,
        "realms": result.get("realms", []),
        "www_authenticate": result.get("www_authenticate", []),
        "proxy_authenticate": result.get("proxy_authenticate", []),
        "error": result.get("error", ""),
    }


def auth_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote auth challenge posture into normalized finding candidates."""
    schemes = schemes_from_payload(payload)
    findings: list[dict[str, object]] = []
    if "BASIC" in schemes and payload.get("scheme") == "http":
        findings.append(
            candidate_payload(
                title="HTTP Basic authentication offered without TLS",
                finding_class="web.auth.basic_over_cleartext",
                severity="medium",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-319"], "owasp": ["A02:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} advertised Basic authentication over HTTP.",
                recommendation="Require HTTPS before Basic authentication is offered or accepted.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    if payload.get("auth_present") and is_adminish_path(str(payload.get("path", ""))):
        findings.append(
            candidate_payload(
                title="Authentication challenge observed on administrative-looking path",
                finding_class="web.auth.admin_challenge_observed",
                severity="info",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_route",
                target=target_payload(payload),
                identifiers={"owasp": ["A01:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} returned authentication challenge schemes: {', '.join(schemes)}.",
                recommendation="Review whether this administrative-looking endpoint is expected to be exposed in scope.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    if "BASIC" in schemes and not realms_from_payload(payload):
        findings.append(
            candidate_payload(
                title="HTTP Basic authentication challenge has no realm",
                finding_class="web.auth.basic_missing_realm",
                severity="low",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-16"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} advertised Basic authentication without a realm value.",
                recommendation="Set a non-sensitive authentication realm so operators can distinguish protected areas.",
                source={"tool": "http_auth", "topic": "http.auth"},
            )
        )
    return findings


def schemes_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return normalized scheme names from a loose event payload."""
    value = payload.get("schemes", ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(scheme).upper() for scheme in value if scheme)


def realms_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return realm values from a loose event payload."""
    value = payload.get("realms", ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(realm) for realm in value if realm)


def is_adminish_path(path: str) -> bool:
    """Return whether a path looks like an administrative or login surface."""
    normalized = path.lower()
    return any(normalized == hint or normalized.startswith(f"{hint}/") for hint in ADMIN_PATH_HINTS)


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
    return HttpAuth()
