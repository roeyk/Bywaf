"""Web fingerprinting commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for HTTP
technology fingerprinting.

Consumes:
- `http.endpoint` events or explicit URL arguments.

Emits:
- `web.fingerprint` for inferred technologies.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool
from bywaf.plugins.http.probe import build_opener, probe_url, target_from_text
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {
    "silent": "false",
    "timeout": 5,
    "user-agent": "Bywaf/0.9",
}


@commandlet(
    name="webfin",
    description="Fingerprint web endpoints from HTTP probe results or explicit targets.",
    usage="webfin [options] [target ...]",
    examples=(
        "http_probe https://example.test/ | webfin",
        "webfin https://example.test/",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_probe --method GET | webfin",
    ),
)
@option("silent", "suppress fingerprint alerts", "false")
@option("timeout", "request timeout seconds", "5")
@option("user-agent", "HTTP User-Agent", "Bywaf/0.9")
class WebFingerprint(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Fingerprint explicit targets or upstream `http.endpoint` events."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        parser.add_argument("--user-agent", default=self.var_default(context, "user-agent", "Bywaf/0.9"))
        parsed = parser.parse_args(args)

        endpoints = endpoint_payloads(parsed.targets, input_events, parsed.timeout, parsed.user_agent, context)
        for endpoint in endpoints:
            fingerprint = fingerprint_endpoint(endpoint)
            context.alert(
                fingerprint_alert(fingerprint),
                silent=parsed.silent,
            )
            yield fingerprint


@dataclass(frozen=True, slots=True)
class Observation:
    """One operator-facing observation about a web endpoint."""

    kind: str
    severity: str
    message: str
    evidence: str = ""

    def as_payload(self) -> dict[str, str]:
        """Return a stable JSON-serializable representation."""
        return {
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


def endpoint_payloads(
    targets: list[str],
    input_events: Iterable[Event],
    timeout: float,
    user_agent: str,
    context: CommandContext,
) -> list[dict[str, Any]]:
    """Resolve endpoint payloads from explicit targets or upstream events."""
    if targets:
        # Explicit targets have not necessarily passed through http_probe, so do
        # a lightweight GET here to collect title/header evidence for inference.
        opener = build_opener(None, None, True)
        payloads: list[dict[str, Any]] = []
        for target in filter_targets_by_host(context, targets, lambda target: target_from_text(target, "auto", "/").host):
            parsed = target_from_text(target, "auto", "/")
            context.audit_capability("network.connect")
            result = probe_url(opener, parsed.url, "GET", timeout, user_agent)
            payloads.append(
                {
                    "url": parsed.url,
                    "host": parsed.host,
                    "port": parsed.port,
                    "scheme": parsed.scheme,
                    **result,
                }
            )
        return payloads
    return [dict(event.payload) for event in input_events if event.topic == "http.endpoint"]


def fingerprint_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Build a structured fingerprint payload for one endpoint."""
    headers = normalized_headers(endpoint.get("headers", {}))
    server = str(endpoint.get("server") or headers.get("server", ""))
    content_type = str(endpoint.get("content_type") or headers.get("content-type", ""))
    title = str(endpoint.get("title") or "")
    status = endpoint.get("status")
    url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    technologies = infer_technologies(server, content_type, title, headers)
    observations = infer_observations(status, server, content_type, title, headers)
    # This plugin emits facts and observations, not findings. Later plugins such
    # as Nikto or report/dedupe can decide which observations are actionable.
    return {
        "url": url,
        "host": str(endpoint.get("host") or ""),
        "port": int(endpoint.get("port") or default_port(str(endpoint.get("scheme") or ""), url)),
        "scheme": str(endpoint.get("scheme") or scheme_from_url(url)),
        "status": status,
        "server": server,
        "content_type": content_type,
        "title": title,
        "technologies": technologies,
        "observations": [observation.as_payload() for observation in observations],
        "interesting": bool(technologies or observations),
    }


def normalized_headers(raw_headers: object) -> dict[str, str]:
    """Normalize response headers to lowercase string keys."""
    if not isinstance(raw_headers, dict):
        return {}
    return {str(key).lower(): str(value) for key, value in raw_headers.items()}


def infer_technologies(
    server: str,
    content_type: str,
    title: str,
    headers: dict[str, str],
) -> list[str]:
    """Infer lightweight technology tags from common HTTP metadata."""
    # Keep rules intentionally shallow. This is a fast triage signal, not a full
    # Wappalyzer-style signature engine.
    evidence = " ".join([server, content_type, title, " ".join(headers.values())]).lower()
    rules = (
        ("nginx", ("nginx",)),
        ("apache", ("apache",)),
        ("iis", ("microsoft-iis", "iis")),
        ("cloudflare", ("cloudflare", "cf-ray")),
        ("php", ("php", "x-powered-by: php")),
        ("asp.net", ("asp.net", "x-aspnet-version")),
        ("wordpress", ("wp-content", "wordpress")),
        ("drupal", ("drupal",)),
        ("jquery", ("jquery",)),
        ("json-api", ("application/json",)),
    )
    found = [name for name, needles in rules if any(needle in evidence for needle in needles)]
    return sorted(dict.fromkeys(found))


def infer_observations(
    status: object,
    server: str,
    content_type: str,
    title: str,
    headers: dict[str, str],
) -> list[Observation]:
    """Generate simple native observations from endpoint metadata."""
    observations: list[Observation] = []
    if isinstance(status, int) and status in {401, 403}:
        observations.append(Observation("access-control", "info", f"restricted endpoint returned HTTP {status}", str(status)))
    if isinstance(status, int) and status >= 500:
        observations.append(Observation("server-error", "medium", f"server returned HTTP {status}", str(status)))
    if server:
        observations.append(Observation("server-header", "info", "server header is exposed", server))
    if "x-powered-by" in headers:
        observations.append(Observation("powered-by", "low", "X-Powered-By header is exposed", headers["x-powered-by"]))
    for header in ("strict-transport-security", "content-security-policy", "x-frame-options"):
        if header not in headers:
            observations.append(Observation("missing-header", "low", f"{canonical_header(header)} header not observed", ""))
    if "index of /" in title.lower():
        observations.append(Observation("directory-listing", "high", "possible directory listing title", title))
    if "text/html" not in content_type.lower() and "application/json" in content_type.lower():
        observations.append(Observation("api-like", "info", "JSON endpoint detected", content_type))
    return observations


def canonical_header(header: str) -> str:
    """Return display casing for a lowercase header name."""
    return "-".join(part.capitalize() for part in header.split("-"))


def fingerprint_alert(payload: dict[str, Any]) -> str:
    """Build a concise console alert for a fingerprint payload."""
    technologies = ",".join(payload.get("technologies", [])) or "unknown"
    observations = payload.get("observations", [])
    return f"fingerprinted {payload.get('url')} tech={technologies} observations={len(observations)}"


def scheme_from_url(url: str) -> str:
    """Infer URL scheme from a URL string."""
    return "https" if url.startswith("https://") else "http"


def default_port(scheme: str, url: str) -> int:
    """Return the default port from scheme or URL."""
    selected = scheme or scheme_from_url(url)
    return 443 if selected == "https" else 80


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return WebFingerprint()
