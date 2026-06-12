"""WAF detection commandlet.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

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
    """Detect common WAF/CDN fingerprints from HTTP response headers.

    Called by: the Bywaf runner when the `waf_detect` commandlet executes.

    Consumes: explicit command-line targets, or upstream `http.endpoint`
    events when used in a pipeline such as `http_probe ... | waf_detect`.

    Emits: `web.waf.detected` events for recognized passive header signals.
    """
    cfg = cast(WafDetectConfig, cfg)
    targets = waf_targets(cfg.targets, input_events)
    scoped_targets = filter_targets_by_host(context, targets, host_from_url)

    for url in scoped_targets:
        # Check the runner cancellation flag before starting the next network
        # operation.
        context.raise_if_cancelled()

        # This audit records actual runtime use of an already-declared
        # capability. Keeping it next to the network call makes audit logs
        # reflect the operation that consumed `network.connect`.
        # Append a runtime capability-use record for this command context.
        context.audit_capability("network.connect")

        # Send a HEAD request and collect the response headers or transport
        # error for this URL.
        result = fetch_headers(url, cfg.timeout, cfg.user_agent)

        # Detection is kept pure: raw fetch results become either a typed
        # schema object or `None`; framework publication happens below.
        # Match the fetched headers against the passive WAF rule table.
        detection = detect_waf(url, result)
        if detection is None:
            continue

        # The structured event is the durable result for reports, pipelines,
        # tests, and downstream plugins. The alert is secondary operator
        # feedback and can be suppressed without losing the data.
        # Persist the typed WAF detection payload in the event store.
        context.events.publish("web.waf.detected", detection.to_payload())
        # Request a one-line operator alert for interactive runs.
        context.alert(f"detected {detection.vendor} WAF signal at {url}", silent=cfg.silent)
    return ()


class WafDetectConfig(RunConfig):
    """Effective runtime configuration for `waf_detect`.

    Constructed by: the framework from manifest defaults plus user-supplied
    arguments/options.

    Used by: `waf_detect()` after casting the generic `RunConfig`.
    """

    targets: list[str]
    silent: bool
    timeout: float
    user_agent: str


def waf_targets(targets: list[str], input_events: Iterable[Event]) -> list[str]:
    """Return target URLs from explicit args or upstream endpoint events.

    Called by: `waf_detect()` before target-policy filtering.

    Explicit targets win. Without explicit targets, this commandlet acts as a
    pipeline consumer and derives URLs from upstream `http.endpoint` events.
    """
    if targets:
        return [normalize_target_url(target) for target in targets]

    # Convert only the event type this plugin declares in `consumes`. The
    # schema object validates/names the payload before we read its URL field.
    # Walk upstream events and extract the URL from each HTTP endpoint payload.
    return [
        HttpEndpoint.from_event(event).url
        for event in input_events
        if event.topic == HttpEndpoint.__topic__
    ]


def normalize_target_url(target: str) -> str:
    """Return an explicit HTTP(S) URL for an operator-supplied target.

    Called by: `waf_targets()` for direct command arguments.
    """
    return target if target.startswith(("http://", "https://")) else f"http://{target}"


def host_from_url(url: str) -> str:
    """Return the hostname used by target-policy filtering.

    Called by: `filter_targets_by_host()` through `waf_detect()`.
    """
    return urllib.parse.urlparse(url).hostname or ""


def fetch_headers(url: str, timeout: float, user_agent: str) -> dict[str, object]:
    """Fetch HTTP response headers with a bounded HEAD request.

    Called by: `waf_detect()` once per scoped target URL.

    The return value is intentionally small and uniform so network failures do
    not interrupt the rest of a multi-target commandlet run.
    """
    if not is_http_url(url):
        return {"error": "unsupported URL scheme", "headers": {}}

    # WAF fingerprints often appear in headers, so HEAD avoids downloading a
    # response body while still preserving the common passive signals.
    # Build a urllib request object for a HEAD request to the target URL.
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": user_agent})
    try:
        # URL scheme is restricted to HTTP(S) above.
        # Open the prepared request URL and expose the HTTP response object.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            # Copy the response status and headers into plain Python objects.
            return {"status": response.status, "headers": dict(response.headers)}
    except urllib.error.HTTPError as exc:
        # HTTP error responses can still carry WAF/CDN headers, so keep them.
        # Copy the error response status and headers into the same result shape.
        return {"status": exc.status, "headers": dict(exc.headers)}
    except urllib.error.URLError as exc:
        # Transport errors provide no headers. The error text is retained for
        # diagnostics while detection simply treats the target as unmatched.
        # Return an empty header map plus a readable transport error string.
        return {"error": str(exc.reason), "headers": {}}


def detect_waf(url: str, result: dict[str, object]) -> WebWafDetected | None:
    """Return a typed WAF detection when fetched headers match a rule.

    Called by: `waf_detect()` after each target's headers are fetched.
    """
    headers = result.get("headers")
    if not isinstance(headers, dict):
        headers = {}

    # Normalize the header map into simple strings so rule predicates can stay
    # case-insensitive and deterministic across urllib response objects.
    # Build a casefolded header dictionary: normalized-name -> string value.
    folded = {str(key).casefold(): str(value) for key, value in headers.items()}

    # Sorted evidence keeps emitted payloads stable for tests and review. The
    # lowercase copy is used for substring matching; the original case is kept
    # in the event payload for operator inspection.
    # Flatten the normalized headers into one deterministic evidence string.
    evidence = " ".join(f"{key}: {value}" for key, value in sorted(folded.items()))
    # Scan the WAF rule dispatch table for the first matching fingerprint.
    rule = matching_waf_rule(folded, evidence.casefold())
    if rule is None:
        return None

    # The schema object centralizes the `web.waf.detected` payload contract and
    # keeps this plugin aligned with the shared event registry.
    # Re-parse the URL so the emitted event includes the hostname separately.
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
    """One passive WAF fingerprinting rule.

    Constructed by: the module-level `WAF_RULES` dispatch table.

    Used by: `matching_waf_rule()` to test normalized headers and evidence.
    """

    vendor: str
    product: str
    matches: Callable[[dict[str, str], str], bool]


def matching_waf_rule(headers: dict[str, str], evidence: str) -> WafRule | None:
    """Return the first WAF rule matching normalized headers.

    Called by: `detect_waf()`. Rule order matters: the first matching entry in
    `WAF_RULES` wins.
    """
    return next((rule for rule in WAF_RULES if rule.matches(headers, evidence)), None)


def has_header(name: str) -> Callable[[dict[str, str], str], bool]:
    """Build a WAF rule predicate for an exact normalized header name."""
    return lambda headers, evidence: name in headers


def evidence_contains(*needles: str) -> Callable[[dict[str, str], str], bool]:
    """Build a WAF rule predicate for lowercase evidence substrings."""
    return lambda headers, evidence: any(needle in evidence for needle in needles)


def any_signal(*predicates: Callable[[dict[str, str], str], bool]) -> Callable[[dict[str, str], str], bool]:
    """Build a predicate that matches when any child signal predicate matches."""
    return lambda headers, evidence: any(predicate(headers, evidence) for predicate in predicates)


def f5_signal(headers: dict[str, str], evidence: str) -> bool:
    """Return whether headers look like an F5 BIG-IP/ASM signal.

    Called by: the F5 entry in `WAF_RULES`.
    """
    return "bigipserver" in evidence or ("f5" in evidence and "x-waf" in headers)


# Dispatch table for passive WAF fingerprinting.
#
# Used by: `matching_waf_rule()`, which walks this table in order instead of
# hard-coding an if/elif ladder. Keeping rule metadata as data makes additions
# and ordering decisions explicit.
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
    """Return whether URL uses an HTTP transport scheme.

    Called by: `fetch_headers()` before urllib opens a network connection.
    """
    return urllib.parse.urlparse(url).scheme in {"http", "https"}


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return waf_detect
