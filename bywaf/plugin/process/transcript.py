"""Process-output artifact transcript helpers.

Used by:
- `ContextProcess.attach_output_artifact()`: store redacted stdout/stderr as a
  durable artifact after a blocking process run.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .audit import redact_known_secret_values
from .models import ProcessResult

if TYPE_CHECKING:
    from ..context import CommandContext


def process_output_artifact_name(result: ProcessResult) -> str:
    """Return a stable display name for one process-output transcript artifact."""
    stem = Path(result.argv[0]).name if result.argv else "process"
    request = f"-{result.request_event_id}" if result.request_event_id is not None else ""
    return f"{stem}{request}-output.txt"


def process_output_transcript(context: CommandContext, result: ProcessResult) -> str:
    """Return an audit-safe process transcript suitable for artifact storage."""
    stdout = redact_known_secret_values(context, result.stdout)
    stderr = redact_known_secret_values(context, result.stderr)
    return "\n".join(
        (
            "argv: " + " ".join(result.argv),
            f"returncode: {result.returncode}",
            f"ok: {str(result.ok).lower()}",
            "",
            "stdout:",
            stdout,
            "",
            "stderr:",
            stderr,
        )
    )
