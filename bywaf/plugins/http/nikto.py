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

import json
import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.nikto_findings import (
    FINDING_TOPICS,
    extract_finding_records,
    finding_identifiers,
    normalize_findings,
    publish_finding,
    publish_tool_problem,
)
from bywaf.plugins.http.http_probe import target_from_text

__all__ = (
    "Nikto",
    "extract_finding_records",
    "finding_identifiers",
    "nikto_argv",
    "nikto_targets",
    "normalize_findings",
    "plugin",
)

DEFAULTS = {
    "binary": "nikto",
    "plugins": "",
    "silent": "false",
    "source": "all",
    "timeout": "300",
    "tuning": "",
}


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
        "db.write:*",
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

        process_artifact_payload = (
            attach_process_output(context, Path(temp_dir), target, result)
            if not result.ok or not output_path.exists()
            else {}
        )
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
                    **process_artifact_payload,
                },
            )

        artifact_payload = attach_raw_output(context, output_path, target) if output_path.exists() else {}
        combined_artifact_payload = {**process_artifact_payload, **artifact_payload}
        data = load_nikto_json(context, output_path, target, combined_artifact_payload)
        findings = normalize_findings(target, data, combined_artifact_payload)
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


def load_nikto_json(
    context: CommandContext,
    output_path: Path,
    target: dict[str, Any],
    artifact_payload: dict[str, Any] | None = None,
) -> Any:
    """Load Nikto JSON output, reporting malformed output as a tool error."""
    if not output_path.exists():
        context.events.publish(
            "tool.error",
            {
                "tool": "nikto",
                "severity": "error",
                "message": "nikto did not produce a JSON output file",
                "target": target,
                **(artifact_payload or {}),
            },
        )
        return {}
    try:
        context.audit_capability("filesystem.read")
        return json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        publish_tool_problem(
            context,
            "tool.error",
            target,
            "nikto produced invalid JSON; raw output artifact attached",
            exc,
            artifact_payload=artifact_payload,
        )
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


def attach_process_output(context: CommandContext, temp_dir: Path, target: dict[str, Any], result: Any) -> dict[str, Any]:
    """Attach stdout/stderr evidence when Nikto output is missing or failed."""
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    returncode = getattr(result, "returncode", None)
    if not stdout and not stderr and returncode == 0:
        return {}
    evidence_path = temp_dir / "nikto-process-output.txt"
    evidence_path.write_text(
        "\n".join(
            (
                f"returncode: {returncode}",
                "",
                "stdout:",
                stdout,
                "",
                "stderr:",
                stderr,
            )
        ),
        encoding="utf-8",
    )
    try:
        artifact = context.artifacts.attach_file(
            evidence_path,
            name=f"nikto-{safe_name(str(target['url']))}-process-output.txt",
            note=f"Nikto stdout/stderr for {target['url']}",
        )
    except (RuntimeError, ValueError) as exc:
        context.events.publish(
            "tool.error",
            {
                "tool": "nikto",
                "severity": "warning",
                "message": "Nikto stdout/stderr was not attached as an artifact",
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
