"""Nikto output loading and artifact attachment helpers.

Used by: `nikto_process.run_target()` after the external Nikto process has
returned or failed to produce structured JSON.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from bywaf.plugin import CommandContext
from bywaf.plugins.http.nikto_findings import publish_tool_problem


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
