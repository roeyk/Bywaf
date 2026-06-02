"""WAF detection commandlet."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import cast

from bywaf.event.schema_objects import HttpEndpoint, WebWafDetected
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, RunConfig, commandlet
from bywaf.plugins.target_policy import filter_targets_by_host


@commandlet
def waf_detect(context: CommandContext, cfg: RunConfig, input_events: Iterable[Event]):
    """Detect common WAF/CDN fingerprints from HTTP headers."""
    cfg = cast(WafDetectConfig, cfg)
    for url in filter_targets_by_host(context, waf_targets(cfg.targets, input_events), host_from_url):
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
        result = fetch_headers(url, cfg.timeout, cfg.user_agent)
        detection = detect_waf(url, result)
        if detection is None:
            continue
        context.events.publish("web.waf.detected", detection.to_payload())
        context.alert(f"detected {detection.vendor} WAF signal at {url}", silent=cfg.silent)
    return ()


class WafDetectConfig(RunConfig):
    """Typed effective config for waf_detect."""

    targets: list[str]
    silent: bool
    timeout: float
    user_agent: str


def waf_targets(targets: list[str], input_events: Iterable[Event]) -> list[str]:
    """Return target URLs from args or upstream endpoints."""
    if targets:
        return [target if target.startswith(("http://", "https://")) else f"http://{target}" for target in targets]
    return [
        HttpEndpoint.from_event(event).url
        for event in input_events
        if event.topic == HttpEndpoint.__topic__
    ]


def host_from_url(url: str) -> str:
    """Return the network host portion of a URL."""
    return urllib.parse.urlparse(url).hostname or ""


def fetch_headers(url: str, timeout: float, user_agent: str) -> dict[str, object]:
    """Fetch response headers with a HEAD request."""
    if not is_http_url(url):
        return {"error": "unsupported URL scheme", "headers": {}}
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": user_agent})
    try:
        # URL scheme is restricted to HTTP(S) above.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            return {"status": response.status, "headers": dict(response.headers)}
    except urllib.error.HTTPError as exc:
        return {"status": exc.status, "headers": dict(exc.headers)}
    except urllib.error.URLError as exc:
        return {"error": str(exc.reason), "headers": {}}


def detect_waf(url: str, result: dict[str, object]) -> WebWafDetected | None:
    """Return a WAF detection from headers when recognized."""
    headers = result.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    folded = {str(key).casefold(): str(value) for key, value in headers.items()}
    evidence = " ".join(f"{key}: {value}" for key, value in sorted(folded.items()))
    rule = matching_waf_rule(folded, evidence.casefold())
    if rule is None:
        return None
    parsed = urllib.parse.urlparse(url)
    return WebWafDetected(
        url=url,
        host=parsed.hostname or "",
        vendor=rule.vendor,
        product=rule.product,
        evidence=evidence[:512],
        confidence="medium",
        scanner="waf_detect",
    )


@dataclass(frozen=True, slots=True)
class WafRule:
    """One WAF signal rule."""

    vendor: str
    product: str
    matches: Callable[[dict[str, str], str], bool]


def matching_waf_rule(headers: dict[str, str], evidence: str) -> WafRule | None:
    """Return the first WAF rule matching normalized headers."""
    return next((rule for rule in WAF_RULES if rule.matches(headers, evidence)), None)


def has_header(name: str) -> Callable[[dict[str, str], str], bool]:
    """Return a predicate for a normalized header name."""
    return lambda headers, evidence: name in headers


def evidence_contains(*needles: str) -> Callable[[dict[str, str], str], bool]:
    """Return a predicate matching any lowercase evidence substring."""
    return lambda headers, evidence: any(needle in evidence for needle in needles)


def any_signal(*predicates: Callable[[dict[str, str], str], bool]) -> Callable[[dict[str, str], str], bool]:
    """Return a predicate that matches when any signal predicate matches."""
    return lambda headers, evidence: any(predicate(headers, evidence) for predicate in predicates)


def f5_signal(headers: dict[str, str], evidence: str) -> bool:
    """Return whether headers look like an F5 BIG-IP/ASM signal."""
    return "bigipserver" in evidence or ("f5" in evidence and "x-waf" in headers)


WAF_RULES = (
    WafRule("Cloudflare", "Cloudflare WAF/CDN", any_signal(has_header("cf-ray"), evidence_contains("cloudflare"))),
    WafRule("Sucuri", "Sucuri WAF", any_signal(has_header("x-sucuri-id"), evidence_contains("sucuri"))),
    WafRule("Akamai", "Akamai edge/WAF", evidence_contains("akamai")),
    WafRule("Imperva", "Imperva Incapsula", any_signal(has_header("x-iinfo"), evidence_contains("incap_ses", "visid_incap"))),
    WafRule("ModSecurity", "ModSecurity", evidence_contains("mod_security", "modsecurity")),
    WafRule("AWS", "AWS ALB/WAF signal", any_signal(has_header("x-amzn-errortype"), evidence_contains("awsalb", "awselb"))),
    WafRule("F5", "F5 BIG-IP/ASM signal", f5_signal),
    WafRule("Barracuda", "Barracuda WAF", evidence_contains("barracuda")),
)


def is_http_url(url: str) -> bool:
    """Return whether URL uses an HTTP transport scheme."""
    return urllib.parse.urlparse(url).scheme in {"http", "https"}


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return waf_detect
