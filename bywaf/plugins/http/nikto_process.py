"""Nikto process execution orchestration.

Used by: `nikto.Nikto` after command parsing and target selection choose the
normalized scan targets.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from bywaf.plugin import CommandContext
from bywaf.plugins.http.nikto_artifacts import attach_process_output, attach_raw_output, load_nikto_json
from bywaf.plugins.http.nikto_findings import normalize_findings, publish_finding, publish_tool_problem


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
