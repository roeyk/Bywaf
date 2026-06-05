"""Publication and summary helpers for finding deduplication."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_dedupe_model import NormalizedFinding
from bywaf.plugins.analysis.finding_dedupe_normalize import stable_finding_id

DecisionPayloadBuilder = Callable[[dict[str, Any], str], dict[str, Any]]
AlertTextBuilder = Callable[[dict[str, Any]], str]

def publish_dedupe_result(context: CommandContext, result: dict[str, Any], *, threshold: float, silent: bool) -> list[Event]:
    """Publish one structured event for every dedupe decision."""
    del threshold
    published = []
    for decision in result["decisions"]:
        kind = str(decision["decision"])
        topic = f"finding.{kind}"
        payload = decision_payload(decision)
        published.append(context.events.publish(topic, payload))
        if not silent:
            context.alert(alert_text(kind, payload), level="finding", silent=False)
    return published


def decision_payload(decision: dict[str, Any]) -> dict[str, Any]:
    """Return the event payload for one dedupe decision."""
    kind = str(decision["decision"])
    finding_id = str(decision["finding_id"])
    builder = decision_payload_builders().get(kind)
    if builder is None:
        raise ValueError(f"unknown dedupe decision: {kind}")
    return builder(decision, finding_id)


def decision_payload_builders() -> dict[str, DecisionPayloadBuilder]:
    """Return dedupe decision payload builders keyed by decision name."""
    return {
        "new": new_decision_payload,
        "duplicate": duplicate_decision_payload,
        "updated": updated_decision_payload,
        "merge_candidate": merge_candidate_decision_payload,
    }


def new_decision_payload(decision: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Return payload for a newly discovered canonical finding."""
    finding = decision["finding"]
    return finding.as_payload(finding_id)


def duplicate_decision_payload(decision: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Return payload for a duplicate finding decision."""
    duplicate = decision["duplicate"]
    return {
        "finding_id": finding_id,
        "duplicate_of": finding_id,
        "matched_on": list(decision["matched_on"]),
        "source": source_payload(duplicate),
    }


def updated_decision_payload(decision: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Return payload for a canonical finding status update."""
    previous = decision["previous"]
    finding = decision["finding"]
    return {
        "finding_id": finding_id,
        "previous_status": previous.status,
        "new_status": finding.status,
        "reason": "higher-confidence status from later source event",
        "source": source_payload(finding),
    }


def merge_candidate_decision_payload(decision: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Return payload for a possible fuzzy merge candidate."""
    candidate = decision["candidate"]
    return {
        "finding_id": finding_id,
        "candidate_for": finding_id,
        "score": round(float(decision["score"]), 3),
        "matched_on": list(decision["matched_on"]),
        "candidate": candidate.as_payload(stable_finding_id(candidate.exact_key())),
    }


def write_summary_artifact(context: CommandContext, result: dict[str, Any], path: Path, format_name: str) -> None:
    """Write a summary file and attach it as a Bywaf artifact."""
    context.audit_capability("filesystem.write")
    path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "md":
        path.write_text(markdown_summary(result), encoding="utf-8")
    else:
        path.write_text(json.dumps(summary_payload(result), indent=2, sort_keys=True), encoding="utf-8")
    context.artifacts.attach_file(path, name=path.name, note="Finding dedupe summary")


def summary_payload(result: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serializable summary of the dedupe result."""
    return {
        "counts": result["counts"],
        "findings": [
            canonical.finding.as_payload(canonical.finding_id)
            for canonical in result["canonical"]
        ],
        "decisions": [
            {"decision": decision["decision"], **decision_payload(decision)}
            for decision in result["decisions"]
        ],
    }


def markdown_summary(result: dict[str, Any]) -> str:
    """Return a compact Markdown summary for operator review."""
    payload = summary_payload(result)
    lines = [
        "# Finding Dedupe Summary",
        "",
        f"- input findings: {sum(payload['counts'].values())}",
        f"- new findings: {payload['counts'].get('new', 0)}",
        f"- duplicates: {payload['counts'].get('duplicate', 0)}",
        f"- updated findings: {payload['counts'].get('updated', 0)}",
        f"- merge candidates: {payload['counts'].get('merge_candidate', 0)}",
        "",
        "| finding | severity | status | class | title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in payload["findings"]:
        lines.append(
            "| {finding_id} | {severity} | {status} | {class_} | {title} |".format(
                finding_id=finding["finding_id"],
                severity=finding.get("severity", ""),
                status=finding.get("status", ""),
                class_=finding.get("class", ""),
                title=str(finding.get("title", "")).replace("|", "\\|"),
            )
        )
    return "\n".join(lines) + "\n"

def source_payload(finding: NormalizedFinding) -> dict[str, Any]:
    """Return compact source metadata for duplicate/update events."""
    return {
        "tool": finding.source_tool,
        "topic": finding.source_topic,
        "event_id": finding.source_event_id,
        "step": finding.source_step,
    }


def summary_line(result: dict[str, Any]) -> str:
    """Return a compact human-facing dedupe summary."""
    counts = result["counts"]
    return (
        "finding_dedupe: "
        f"{counts.get('new', 0)} new, "
        f"{counts.get('duplicate', 0)} duplicate, "
        f"{counts.get('updated', 0)} updated, "
        f"{counts.get('merge_candidate', 0)} merge candidate"
    )


def alert_text(kind: str, payload: dict[str, Any]) -> str:
    """Return compact alert text for one dedupe decision."""
    builder = alert_text_builders().get(kind)
    return builder(payload) if builder is not None else kind


def alert_text_builders() -> dict[str, AlertTextBuilder]:
    """Return alert text builders keyed by dedupe decision name."""
    return {
        "new": lambda payload: (
            f"new {payload.get('severity')} {payload.get('status')} "
            f"{payload.get('class')} {payload.get('title')}"
        ),
        "duplicate": lambda payload: (
            f"duplicate of {payload.get('duplicate_of')} from {payload.get('source', {}).get('tool')}"
        ),
        "updated": lambda payload: (
            f"updated {payload.get('finding_id')} {payload.get('previous_status')} -> {payload.get('new_status')}"
        ),
        "merge_candidate": lambda payload: (
            f"merge candidate {payload.get('finding_id')} score={payload.get('score')}"
        ),
    }
