"""Nikto target collection and policy filtering.

Used by:
- `nikto.Nikto` to resolve explicit targets and upstream HTTP/web fingerprint
  events into normalized scan targets.
- EyeWitness and repository-exposure plugins for shared HTTP target helpers.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.http_probe import target_from_text
from bywaf.plugins.target_policy import filter_targets_by_host


def nikto_targets(targets: list[str], input_events: Iterable[Event], source: str) -> list[dict[str, Any]]:
    """Resolve Nikto targets from explicit args or upstream web events."""
    resolved: list[dict[str, Any]] = []
    if targets:
        resolved.extend(target_payload_from_text(target) for target in targets)
        if source == "explicit":
            return dedupe_targets(resolved)
    if source == "explicit":
        return dedupe_targets(resolved)

    events = list(input_events)
    # `source` lets operators choose whether Nikto scans only web fingerprints,
    # only explicit CLI targets, or all upstream HTTP endpoint evidence.
    if source in {"all", "webfin"}:
        resolved.extend(target_from_webfin_event(event) for event in events if event.topic == "web.fingerprint")
    if source == "all":
        resolved.extend(target_from_endpoint_event(event) for event in events if event.topic == "http.endpoint")
    return dedupe_targets(target for target in resolved if target)


def target_payload_from_text(target: str) -> dict[str, Any]:
    """Normalize a CLI target into the target payload used in finding events."""
    parsed = target_from_text(target, "auto", "/")
    return {
        "url": parsed.url,
        "host": parsed.host,
        "port": parsed.port,
        "scheme": parsed.scheme,
        "source": "explicit",
    }


def target_from_endpoint_event(event: Event) -> dict[str, Any]:
    """Normalize one `http.endpoint` event as a Nikto target."""
    payload = dict(event.payload)
    url = str(payload.get("final_url") or payload.get("url") or "")
    if not url:
        return {}
    parsed = target_from_text(url, "auto", "/")
    return {
        "url": parsed.url,
        "host": str(payload.get("host") or parsed.host),
        "port": int(payload.get("port") or parsed.port),
        "scheme": str(payload.get("scheme") or parsed.scheme),
        "source": "http.endpoint",
        "event_id": event.id,
    }


def target_from_webfin_event(event: Event) -> dict[str, Any]:
    """Normalize one `web.fingerprint` event as a Nikto target."""
    payload = dict(event.payload)
    if not bool(payload.get("interesting", True)):
        return {}
    url = str(payload.get("url") or "")
    if not url:
        return {}
    parsed = target_from_text(url, "auto", "/")
    return {
        "url": parsed.url,
        "host": str(payload.get("host") or parsed.host),
        "port": int(payload.get("port") or parsed.port),
        "scheme": str(payload.get("scheme") or parsed.scheme),
        "source": "web.fingerprint",
        "event_id": event.id,
    }


def dedupe_targets(targets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate target payloads by URL while preserving first-seen order."""
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for target in targets:
        url = str(target.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(target)
    return deduped


def filter_http_payloads_by_policy(context: CommandContext, targets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return HTTP target payloads whose host passes framework policy."""
    return filter_targets_by_host(context, targets, lambda target: str(target.get("host") or ""))
