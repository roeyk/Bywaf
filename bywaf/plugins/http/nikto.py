"""Nikto wrapper commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for the
external Nikto scanner.

Consumes:
- `http.endpoint` or `web.fingerprint` events, or explicit URL arguments.

Emits:
- `nikto.finding` for parsed Nikto records.
- `vulnerability.found` and `vulnerability.potential` compatibility events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.http_probe import target_from_text

DEFAULTS = {
    "binary": "nikto",
    "plugins": "",
    "silent": "false",
    "source": "all",
    "timeout": "300",
    "tuning": "",
}

FINDING_TOPICS = (
    "nikto.finding",
    "vulnerability.found",
    "vulnerability.potential",
)


@commandlet(
    name="nikto",
    description="Run Nikto against HTTP endpoints and emit normalized findings.",
    usage="nikto [options] [target ...]",
    examples=(
        "nikto https://example.test/",
        "http_probe https://example.test/ | nikto",
        "http_probe https://example.test/ | webfin | nikto source=webfin",
    ),
    consumes=("http.endpoint", "web.fingerprint"),
    emits=FINDING_TOPICS,
    capabilities=(
        "artifact.write",
        "db.write:nikto.finding",
        "db.write:vulnerability.found",
        "db.write:vulnerability.potential",
        "db.write:tool.error",
        "db.write:tool.exception",
        "db.write:system.error",
        "db.write:network.error",
        "db.write:web.error",
        "filesystem.read",
        "filesystem.write",
        "framework.console.alert",
        "framework.process.run",
        "network.connect",
        "process.run",
    ),
)
@option("binary", "Nikto executable", "nikto", completion="path")
@option("plugins", "Nikto plugin selector")
@option("silent", "suppress finding alerts", "false")
@option("source", "endpoint source", "all", ("all", "explicit", "webfin"))
@option("timeout", "seconds per target", "300")
@option("tuning", "Nikto tuning selector")
class Nikto(CommandletBase):
    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run Nikto for explicit targets or upstream HTTP endpoint events."""
        parser = self.parser()
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--binary", default=self.var_default(context, "binary", "nikto"))
        parser.add_argument("--plugins", default=self.var_default(context, "plugins", ""))
        parser.add_argument("--source", choices=("all", "explicit", "webfin"), default=self.var_default(context, "source", "all"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 300, cast=float))
        parser.add_argument("--tuning", default=self.var_default(context, "tuning", ""))
        parsed = parser.parse_args(args)

        targets = nikto_targets(parsed.targets, input_events, parsed.source)
        if not targets:
            context.events.publish(
                "tool.error",
                {
                    "tool": "nikto",
                    "severity": "warning",
                    "message": "no HTTP endpoints selected for Nikto scan",
                    "source": parsed.source,
                },
            )
            return ()

        for target in targets:
            context.raise_if_cancelled()
            run_target(context, parsed, target)
        return ()


def run_target(context: CommandContext, parsed: Any, target: dict[str, Any]) -> None:
    """Run Nikto for one normalized target and publish findings/errors."""
    url = str(target["url"])
    context.audit_capability("network.connect")
    with tempfile.TemporaryDirectory(prefix="bywaf-nikto-") as temp_dir:
        output_path = Path(temp_dir, "nikto.json")
        # Nikto writes structured output to a file. Run it shell-free, then
        # import the produced JSON as both parse input and optional artifact.
        argv = nikto_argv(
            binary=str(parsed.binary),
            url=url,
            output_path=output_path,
            tuning=str(parsed.tuning or ""),
            plugins=str(parsed.plugins or ""),
        )
        try:
            result = context.process.run(argv, timeout=float(parsed.timeout))
        except FileNotFoundError as exc:
            publish_tool_problem(context, "system.error", target, "nikto executable not found", exc)
            return
        except subprocess.TimeoutExpired as exc:
            publish_tool_problem(context, "tool.error", target, "nikto scan timed out", exc)
            return
        except OSError as exc:
            publish_tool_problem(context, "system.error", target, "could not execute nikto", exc)
            return

        if not result.ok:
            context.events.publish(
                "tool.error",
                {
                    "tool": "nikto",
                    "severity": "error",
                    "message": f"nikto exited with status {result.returncode}",
                    "target": target,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            )

        data = load_nikto_json(context, output_path, target)
        artifact_payload = attach_raw_output(context, output_path, target) if output_path.exists() else {}
        findings = normalize_findings(target, data, artifact_payload)
        for finding in findings:
            publish_finding(context, finding, silent=bool(parsed.silent))


def nikto_argv(
    *,
    binary: str,
    url: str,
    output_path: Path,
    tuning: str,
    plugins: str,
) -> list[str]:
    """Build a shell-free Nikto argv vector."""
    argv = [
        binary,
        "-host",
        url,
        "-Format",
        "json",
        "-output",
        str(output_path),
        "-nointeractive",
    ]
    if tuning:
        argv.extend(["-Tuning", tuning])
    if plugins:
        argv.extend(["-Plugins", plugins])
    return argv


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


def load_nikto_json(context: CommandContext, output_path: Path, target: dict[str, Any]) -> Any:
    """Load Nikto JSON output, reporting malformed output as a tool error."""
    if not output_path.exists():
        context.events.publish(
            "tool.error",
            {
                "tool": "nikto",
                "severity": "error",
                "message": "nikto did not produce a JSON output file",
                "target": target,
            },
        )
        return {}
    try:
        context.audit_capability("filesystem.read")
        return json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        publish_tool_problem(context, "tool.error", target, "nikto produced invalid JSON", exc)
        return {}


def attach_raw_output(context: CommandContext, output_path: Path, target: dict[str, Any]) -> dict[str, Any]:
    """Attach raw Nikto JSON when artifact storage is available."""
    try:
        artifact = context.artifacts.attach_file(
            output_path,
            name=f"nikto-{safe_name(str(target['url']))}.json",
            note=f"Raw Nikto JSON for {target['url']}",
        )
    except (RuntimeError, ValueError) as exc:
        context.events.publish(
            "tool.error",
            {
                "tool": "nikto",
                "severity": "warning",
                "message": "raw Nikto JSON was not attached as an artifact",
                "target": target,
                "error": str(exc),
            },
        )
        return {}
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "artifact_sha256": artifact.sha256,
    }


def normalize_findings(target: dict[str, Any], data: Any, artifact_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Nikto-specific records into Bywaf vulnerability payloads."""
    findings: list[dict[str, Any]] = []
    for record in extract_finding_records(data):
        message = finding_message(record)
        if not message:
            continue
        identifiers = finding_identifiers(record)
        finding_id = stable_finding_id(target, record, message)
        severity = str(record.get("severity") or record.get("level") or "unknown")
        path = str(record.get("url") or record.get("uri") or record.get("path") or "")
        method = str(record.get("method") or "")
        # This wrapper emits both Nikto-native and compatibility topics. The
        # normalized fields below give finding_dedupe/report enough structure to
        # group results even before a dedicated candidate_payload migration.
        finding = {
            "finding_id": finding_id,
            "scanner": "nikto",
            "tool": "nikto",
            "target": target,
            "url": target["url"],
            "host": target.get("host", ""),
            "port": target.get("port"),
            "scheme": target.get("scheme", ""),
            "title": message,
            "message": message,
            "evidence": finding_evidence(record),
            "path": path,
            "method": method,
            "severity": severity,
            "confidence": str(record.get("confidence") or "medium"),
            "verification": "potential",
            "identifiers": identifiers,
            "raw": record,
            **artifact_payload,
        }
        findings.append(finding)
    return findings


def extract_finding_records(data: Any) -> list[dict[str, Any]]:
    """Extract finding-like dictionaries from common Nikto JSON layouts."""
    records: list[dict[str, Any]] = []
    if isinstance(data, list):
        for item in data:
            records.extend(extract_finding_records(item))
        return records
    if not isinstance(data, dict):
        return records

    for key in ("vulnerabilities", "findings", "items"):
        value = data.get(key)
        if isinstance(value, list):
            records.extend(dict(item) for item in value if isinstance(item, dict))

    if is_finding_record(data):
        records.append(dict(data))

    for value in data.values():
        if isinstance(value, (dict, list)):
            # Nikto JSON layouts vary across versions and wrappers. Recursing
            # lets us support nested records without committing to one schema.
            records.extend(extract_finding_records(value))
    return unique_records(records)


def is_finding_record(record: dict[str, Any]) -> bool:
    """Return whether a dictionary looks like a Nikto finding."""
    keys = {key.lower() for key in record}
    return bool(keys & {"msg", "message", "description"}) and bool(keys & {"id", "uri", "url", "osvdb", "cve"})


def unique_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate record objects produced by recursive extraction."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for record in records:
        marker = json.dumps(record, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(record)
    return unique


def finding_message(record: dict[str, Any]) -> str:
    """Return the best human-facing message from a Nikto finding record."""
    for key in ("msg", "message", "description", "name", "title"):
        value = record.get(key)
        if value:
            return str(value)
    return ""


def finding_evidence(record: dict[str, Any]) -> str:
    """Return compact evidence text from a Nikto finding record."""
    for key in ("evidence", "data", "details", "references"):
        value = record.get(key)
        if value:
            return str(value)
    return ""


def finding_identifiers(record: dict[str, Any]) -> dict[str, list[str]]:
    """Extract CVE/CWE/OWASP/vendor identifiers from a finding record."""
    text = json.dumps(record, sort_keys=True, default=str)
    identifiers: dict[str, list[str]] = {
        "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE))),
        "cwe": sorted(set(identifier.upper() for identifier in re.findall(r"CWE-\d+", text, re.IGNORECASE))),
        "owasp": sorted(set(re.findall(r"A\d{2}:20\d{2}", text, re.IGNORECASE))),
        "vendor": [],
    }
    nikto_id = record.get("id") or record.get("nikto_id") or record.get("test_id")
    if nikto_id:
        identifiers["vendor"].append(f"nikto:{nikto_id}")
    osvdb = record.get("OSVDB") or record.get("osvdb")
    if osvdb:
        identifiers["vendor"].append(f"osvdb:{osvdb}")
    return {key: values for key, values in identifiers.items() if values}


def stable_finding_id(target: dict[str, Any], record: dict[str, Any], message: str) -> str:
    """Return a deterministic finding ID for lifecycle correlation."""
    basis = "|".join(
        [
            str(target.get("url", "")),
            str(record.get("id") or record.get("OSVDB") or record.get("osvdb") or ""),
            str(record.get("url") or record.get("uri") or record.get("path") or ""),
            message,
        ]
    )
    return f"nikto-{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:16]}"


def publish_finding(context: CommandContext, finding: dict[str, Any], *, silent: bool) -> None:
    """Publish Nikto-specific, generic, and lifecycle finding events."""
    for topic in FINDING_TOPICS:
        context.events.publish(topic, finding)
    context.alert(
        f"nikto potential finding {finding['url']} {finding['title']}",
        level="finding",
        silent=silent,
    )


def publish_tool_problem(
    context: CommandContext,
    topic: str,
    target: dict[str, Any],
    message: str,
    exc: BaseException,
) -> None:
    """Publish a normalized operational problem from the Nikto wrapper."""
    context.events.publish(
        topic,
        {
            "tool": "nikto",
            "severity": "error",
            "message": message,
            "target": target,
            "exception": exc.__class__.__name__,
            "error": str(exc),
        },
    )


def safe_name(value: str) -> str:
    """Return a filesystem-friendly short name for artifact titles."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned[:80] or "target"


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Nikto()
