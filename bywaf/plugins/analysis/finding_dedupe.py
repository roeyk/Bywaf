"""Normalize and deduplicate vulnerability/finding events."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins._args import key_value_to_long_options

FINDING_INPUT_TOPICS = (
    "nikto.finding",
    "vulnerability.found",
    "vulnerability.potential",
    "vulnerability.confirmed",
    "vulnerability.speculative",
    "vulnerability.false_positive",
)
FINDING_OUTPUT_TOPICS = (
    "finding.new",
    "finding.duplicate",
    "finding.updated",
    "finding.merge_candidate",
)
STATUS_RANKS = {
    "false_positive": 0,
    "speculative": 1,
    "potential": 2,
    "confirmed": 3,
}
OPTION_KEYS = {"file", "format", "limit", "threshold"}
DecisionPayloadBuilder = Callable[[dict[str, Any], str], dict[str, Any]]
AlertTextBuilder = Callable[[dict[str, Any]], str]


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    """Canonical identity of the affected target."""

    scheme: str = ""
    host: str = ""
    port: str = ""
    path: str = ""
    parameter: str = ""
    service: str = ""
    product: str = ""
    version: str = ""

    def as_payload(self) -> dict[str, str]:
        """Return non-empty target fields for event payloads."""
        values = {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "parameter": self.parameter,
            "service": self.service,
            "product": self.product,
            "version": self.version,
        }
        return {key: value for key, value in values.items() if value}

    def key(self) -> str:
        """Return a deterministic key used for dedupe comparisons."""
        return "|".join(
            (
                self.scheme,
                self.host,
                self.port,
                self.path,
                self.parameter,
                self.service,
                self.product,
                self.version,
            )
        )


@dataclass(slots=True)
class NormalizedFinding:
    """Tool-neutral finding representation used by the deduper."""

    source_event_id: int | None
    source_topic: str
    source_tool: str
    source_run: str | None
    title: str
    finding_class: str
    status: str
    confidence: str
    severity: str
    target: TargetIdentity
    identifiers: dict[str, list[str]]
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def exact_key(self) -> str:
        """Return the strongest available dedupe key for this finding."""
        identifier = best_identifier(self.identifiers)
        if identifier:
            return "|".join(("id", self.target.key(), identifier))
        return "|".join(("fingerprint", self.target.key(), self.finding_class, evidence_fingerprint(self)))

    def fuzzy_basis(self) -> str:
        """Return normalized text used for last-resort fuzzy candidate checks."""
        return normalize_text(" ".join([self.title, self.evidence]))

    def as_payload(self, finding_id: str) -> dict[str, Any]:
        """Return the canonical event payload for this finding."""
        return {
            "finding_id": finding_id,
            "status": self.status,
            "confidence": self.confidence,
            "severity": self.severity,
            "class": self.finding_class,
            "title": self.title,
            "target": self.target.as_payload(),
            "identifiers": self.identifiers,
            "evidence": self.evidence,
            "sources": [
                {
                    "tool": self.source_tool,
                    "topic": self.source_topic,
                    "event_id": self.source_event_id,
                    "run": self.source_run,
                }
            ],
        }


@dataclass(slots=True)
class CanonicalFinding:
    """One deduped finding and the source events attached to it."""

    finding_id: str
    finding: NormalizedFinding
    source_event_ids: list[int | None] = field(default_factory=list)

    def add_source(self, finding: NormalizedFinding) -> None:
        """Remember the source event that contributed to this finding."""
        self.source_event_ids.append(finding.source_event_id)


@commandlet(
    name="finding_dedupe",
    description="Normalize and deduplicate vulnerability finding events.",
    usage="finding_dedupe [file=summary.json|summary.md] [format=json|md] [threshold=0.82]",
    examples=(
        "nikto source=webfin | finding_dedupe",
        "finding_dedupe file=dedupe-summary.json",
        "finding_dedupe format=md file=findings.md",
    ),
    consumes=FINDING_INPUT_TOPICS,
    emits=FINDING_OUTPUT_TOPICS,
    capabilities=(
        "artifact.write",
        "db.read:nikto.finding",
        "db.read:vulnerability.found",
        "db.read:vulnerability.potential",
        "db.read:vulnerability.confirmed",
        "db.read:vulnerability.speculative",
        "db.read:vulnerability.false_positive",
        "db.write:finding.new",
        "db.write:finding.duplicate",
        "db.write:finding.updated",
        "db.write:finding.merge_candidate",
        "filesystem.read",
        "filesystem.write",
        "framework.console.output",
    ),
)
@option("file", "write and attach a JSON or Markdown dedupe summary", completion="path")
@option("format", "summary format", "json", ("json", "md"))
@option("limit", "maximum historical input events when no pipeline input exists", "1000")
@option("threshold", "minimum fuzzy score for merge candidates", "0.82")
class FindingDedupe(CommandletBase):
    """Build normalized finding records without destroying original tool output."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Deduplicate input findings and publish normalized finding events."""
        parser = self.parser()
        parser.add_argument("-s", "--silent", action="store_true")
        parser.add_argument("--file", default="")
        parser.add_argument("--format", choices=("json", "md"), default="json")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--threshold", type=float, default=0.82)
        parsed = parser.parse_args(key_value_to_long_options(args, OPTION_KEYS))

        events = selected_finding_events(context, list(input_events), parsed.limit)
        result = dedupe_findings(
            (normalize_event(event) for event in events if event.topic in FINDING_INPUT_TOPICS),
            fuzzy_threshold=float(parsed.threshold),
        )
        publish_dedupe_result(context, result, threshold=float(parsed.threshold), silent=bool(parsed.silent))
        if parsed.file:
            write_summary_artifact(context, result, Path(parsed.file).expanduser(), str(parsed.format))
        context.output(summary_line(result))
        return ()


def selected_finding_events(context: CommandContext, input_events: list[Event], limit: int) -> list[Event]:
    """Use pipeline input first, otherwise query historical finding topics."""
    selected = [event for event in input_events if event.topic in FINDING_INPUT_TOPICS]
    if selected:
        return selected
    events: list[Event] = []
    for topic in FINDING_INPUT_TOPICS:
        events.extend(context.events.query(topic=topic, limit=limit))
    return sorted(events, key=lambda event: event.id or 0)


def normalize_event(event: Event) -> NormalizedFinding:
    """Convert one source event into a tool-neutral finding candidate."""
    payload = dict(event.payload)
    title = first_text(payload, "title", "message", "description", "name") or event.topic
    target = normalize_target(payload)
    identifiers = normalize_identifiers(payload)
    finding_class = str(payload.get("class") or payload.get("kind") or infer_finding_class(title, payload))
    return NormalizedFinding(
        source_event_id=event.id,
        source_topic=event.topic,
        source_tool=str(payload.get("tool") or payload.get("scanner") or event.source),
        source_run=event.command_run_id,
        title=title,
        finding_class=finding_class,
        status=normalize_status(str(payload.get("status") or payload.get("verification") or status_from_topic(event.topic))),
        confidence=str(payload.get("confidence") or "medium"),
        severity=str(payload.get("severity") or "unknown"),
        target=target,
        identifiers=identifiers,
        evidence=first_text(payload, "evidence", "proof", "details", "data") or "",
        raw=payload,
    )


def dedupe_findings(findings: Iterable[NormalizedFinding], *, fuzzy_threshold: float = 0.82) -> dict[str, Any]:
    """Classify findings as new, duplicate, update, or candidate merge."""
    canonical_by_key: dict[str, CanonicalFinding] = {}
    canonical: list[CanonicalFinding] = []
    decisions: list[dict[str, Any]] = []
    for finding in findings:
        key = finding.exact_key()
        existing = canonical_by_key.get(key)
        if existing is None:
            fuzzy = best_fuzzy_candidate(finding, canonical, threshold=fuzzy_threshold)
            if fuzzy is None:
                finding_id = stable_finding_id(key)
                existing = CanonicalFinding(finding_id, finding, [finding.source_event_id])
                canonical_by_key[key] = existing
                canonical.append(existing)
                decisions.append({"decision": "new", "finding_id": finding_id, "finding": finding})
                continue
            decisions.append(
                {
                    "decision": "merge_candidate",
                    "finding_id": fuzzy[0].finding_id,
                    "candidate": finding,
                    "score": fuzzy[1],
                    "matched_on": ["target", "class", "fuzzy_text"],
                }
            )
            continue

        existing.add_source(finding)
        if status_rank(finding.status) > status_rank(existing.finding.status):
            previous = existing.finding
            existing.finding = finding
            decisions.append(
                {
                    "decision": "updated",
                    "finding_id": existing.finding_id,
                    "previous": previous,
                    "finding": finding,
                }
            )
        else:
            decisions.append(
                {
                    "decision": "duplicate",
                    "finding_id": existing.finding_id,
                    "duplicate": finding,
                    "matched_on": matched_on(finding),
                }
            )
    return {
        "canonical": canonical,
        "decisions": decisions,
        "counts": count_decisions(decisions),
    }


def publish_dedupe_result(context: CommandContext, result: dict[str, Any], *, threshold: float, silent: bool) -> None:
    """Publish one structured event for every dedupe decision."""
    del threshold
    for decision in result["decisions"]:
        kind = str(decision["decision"])
        topic = f"finding.{kind}"
        payload = decision_payload(decision)
        context.events.publish(topic, payload)
        if not silent:
            context.alert(alert_text(kind, payload), level="finding", silent=False)


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


def best_fuzzy_candidate(
    finding: NormalizedFinding,
    canonical: list[CanonicalFinding],
    threshold: float = 0.82,
) -> tuple[CanonicalFinding, float] | None:
    """Return a fuzzy merge candidate when target and class already match."""
    best: tuple[CanonicalFinding, float] | None = None
    for candidate in canonical:
        if candidate.finding.target.key() != finding.target.key():
            continue
        if candidate.finding.finding_class != finding.finding_class:
            continue
        score = SequenceMatcher(None, finding.fuzzy_basis(), candidate.finding.fuzzy_basis()).ratio()
        if score >= threshold and (best is None or score > best[1]):
            best = (candidate, score)
    return best


def normalize_target(payload: dict[str, Any]) -> TargetIdentity:
    """Normalize target identity from common finding payload shapes."""
    target = payload.get("target")
    target_payload = target if isinstance(target, dict) else {}
    url = str(payload.get("url") or target_payload.get("url") or "")
    parsed = urlparse(url)
    scheme = str(target_payload.get("scheme") or payload.get("scheme") or parsed.scheme or "")
    host = str(target_payload.get("host") or payload.get("host") or parsed.hostname or "")
    port = str(target_payload.get("port") or payload.get("port") or parsed.port or default_port(scheme))
    path = str(target_payload.get("path") or payload.get("path") or parsed.path or "/")
    return TargetIdentity(
        scheme=scheme.lower(),
        host=host.lower(),
        port=port,
        path=normalize_path(path),
        parameter=str(payload.get("parameter") or target_payload.get("parameter") or ""),
        service=str(payload.get("service") or target_payload.get("service") or ""),
        product=str(payload.get("product") or target_payload.get("product") or ""),
        version=str(payload.get("version") or target_payload.get("version") or ""),
    )


def normalize_identifiers(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Normalize explicit and embedded vulnerability identifiers."""
    identifiers: dict[str, list[str]] = {}
    raw = payload.get("identifiers")
    if isinstance(raw, dict):
        for key, value in raw.items():
            values = value if isinstance(value, list) else [value]
            identifiers[str(key).lower()] = sorted({str(item) for item in values if str(item)})
    text = json.dumps(payload, sort_keys=True, default=str)
    add_identifiers(identifiers, "cve", re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE))
    add_identifiers(identifiers, "cwe", re.findall(r"CWE-\d+", text, re.IGNORECASE))
    add_identifiers(identifiers, "ghsa", re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text, re.IGNORECASE))
    add_identifiers(identifiers, "osv", re.findall(r"OSV-\d+", text, re.IGNORECASE))
    return {key: sorted({value.upper() if key in {"cve", "cwe", "ghsa", "osv"} else value for value in values}) for key, values in identifiers.items() if values}


def add_identifiers(identifiers: dict[str, list[str]], key: str, values: list[str]) -> None:
    """Merge identifier values into a normalized identifier dictionary."""
    identifiers.setdefault(key, [])
    identifiers[key].extend(values)


def best_identifier(identifiers: dict[str, list[str]]) -> str:
    """Return the strongest standardized identifier for exact matching."""
    for key in ("cve", "ghsa", "osv", "cwe", "vendor", "owasp"):
        values = identifiers.get(key, [])
        if values:
            return f"{key}:{values[0]}"
    return ""


def infer_finding_class(title: str, payload: dict[str, Any]) -> str:
    """Infer a stable finding class from common vulnerability wording."""
    text = normalize_text(" ".join([title, json.dumps(payload, default=str)]))
    rules = (
        ("missing_security_header", ("missing", "header")),
        ("directory_listing", ("directory listing",)),
        ("directory_listing", ("index of",)),
        ("default_credentials", ("default credential", "default password")),
        ("known_vulnerable_component", ("cve-", "vulnerable", "outdated")),
        ("exposed_admin_interface", ("admin", "administrator", "login")),
        ("tls_weak_cipher", ("weak cipher", "tls", "ssl")),
        ("sql_injection_possible", ("sql injection", "sqli")),
    )
    for name, needles in rules:
        if all(needle in text for needle in needles):
            return name
    return "generic_finding"


def evidence_fingerprint(finding: NormalizedFinding) -> str:
    """Return a hash of stable finding fields when identifiers are absent."""
    basis = "|".join(
        [
            finding.title.lower(),
            finding.evidence.lower(),
            json.dumps(finding.identifiers, sort_keys=True),
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def stable_finding_id(key: str) -> str:
    """Return a stable normalized finding id."""
    return f"finding-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"


def matched_on(finding: NormalizedFinding) -> list[str]:
    """Describe the match evidence for duplicate decisions."""
    fields = ["target"]
    fields.append("identifier" if best_identifier(finding.identifiers) else "fingerprint")
    if finding.finding_class:
        fields.append("class")
    return fields


def count_decisions(decisions: list[dict[str, Any]]) -> dict[str, int]:
    """Count decisions by type."""
    counts = {key: 0 for key in ("new", "duplicate", "updated", "merge_candidate")}
    for decision in decisions:
        counts[str(decision["decision"])] += 1
    return counts


def source_payload(finding: NormalizedFinding) -> dict[str, Any]:
    """Return compact source metadata for duplicate/update events."""
    return {
        "tool": finding.source_tool,
        "topic": finding.source_topic,
        "event_id": finding.source_event_id,
        "run": finding.source_run,
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


def first_text(payload: dict[str, Any], *keys: str) -> str:
    """Return the first non-empty string-like payload value."""
    for key in keys:
        value = payload.get(key)
        if value:
            return str(value)
    return ""


def status_from_topic(topic: str) -> str:
    """Infer verification status from the source topic."""
    if topic.endswith(".confirmed") or topic == "vulnerability.found":
        return "confirmed"
    if topic.endswith(".false_positive"):
        return "false_positive"
    if topic.endswith(".speculative"):
        return "speculative"
    return "potential"


def normalize_status(value: str) -> str:
    """Normalize status words to Bywaf finding lifecycle values."""
    cleaned = value.strip().lower().replace("-", "_")
    aliases = {"found": "confirmed", "possible": "potential", "unverified": "potential"}
    return aliases.get(cleaned, cleaned if cleaned in STATUS_RANKS else "potential")


def status_rank(status: str) -> int:
    """Return comparable status strength."""
    return STATUS_RANKS.get(normalize_status(status), STATUS_RANKS["potential"])


def normalize_text(value: str) -> str:
    """Normalize free text for comparison."""
    return re.sub(r"\s+", " ", value.lower()).strip()


def normalize_path(value: str) -> str:
    """Normalize URL paths without dropping root."""
    if not value:
        return "/"
    return value if value.startswith("/") else f"/{value}"


def default_port(scheme: str) -> str:
    """Return the default port for common URL schemes."""
    return {"http": "80", "https": "443"}.get(scheme.lower(), "")


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return FindingDedupe()
