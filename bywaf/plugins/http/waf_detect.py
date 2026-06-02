"""WAF detection commandlet."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
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
    vendor = ""
    product = ""
    if "cf-ray" in folded or "cloudflare" in evidence.casefold():
        vendor, product = "Cloudflare", "Cloudflare WAF/CDN"
    elif "x-sucuri-id" in folded or "sucuri" in evidence.casefold():
        vendor, product = "Sucuri", "Sucuri WAF"
    elif "akamai" in evidence.casefold():
        vendor, product = "Akamai", "Akamai edge/WAF"
    elif "incap_ses" in evidence.casefold() or "visid_incap" in evidence.casefold() or "x-iinfo" in folded:
        vendor, product = "Imperva", "Imperva Incapsula"
    elif "mod_security" in evidence.casefold() or "modsecurity" in evidence.casefold():
        vendor, product = "ModSecurity", "ModSecurity"
    elif "x-amzn-errortype" in folded or "awsalb" in evidence.casefold() or "awselb" in evidence.casefold():
        vendor, product = "AWS", "AWS ALB/WAF signal"
    elif "bigipserver" in evidence.casefold() or ("f5" in evidence.casefold() and "x-waf" in folded):
        vendor, product = "F5", "F5 BIG-IP/ASM signal"
    elif "barracuda" in evidence.casefold():
        vendor, product = "Barracuda", "Barracuda WAF"
    if not vendor:
        return None
    parsed = urllib.parse.urlparse(url)
    return WebWafDetected(
        url=url,
        host=parsed.hostname or "",
        vendor=vendor,
        product=product,
        evidence=evidence[:512],
        confidence="medium",
        scanner="waf_detect",
    )


def is_http_url(url: str) -> bool:
    """Return whether URL uses an HTTP transport scheme."""
    return urllib.parse.urlparse(url).scheme in {"http", "https"}


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return waf_detect
