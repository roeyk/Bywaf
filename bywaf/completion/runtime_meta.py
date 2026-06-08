"""Runtime completion metadata helpers.

Provides prompt-toolkit display metadata for job, step, and pipeline
completion candidates.

Used by:
- completion.engine: mixes runtime metadata into CoreCompleter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .runtime import runtime_completion_target

if TYPE_CHECKING:
    from ..db import EventStore


class RuntimeCompletionMetadataMixin:
    """Prompt metadata helpers for runtime-backed completion candidates."""

    db: "EventStore | None"

    def completion_meta(self, candidate: str, line: str, prefix: str) -> str:
        """Return prompt-toolkit metadata for runtime entity completions."""
        if self.db is None:
            return ""
        kind, value = runtime_completion_target(candidate, line, prefix)
        if kind is None or not value:
            return ""
        # Runtime selector completions can show different metadata depending on
        # whether the candidate names a job, pipeline, or step. completion_meta()
        # uses this dispatch table after runtime_completion_target() identifies the kind.
        dispatch = {
            "job": self.job_completion_meta,
            "pipeline": self.pipeline_completion_meta,
            "step": self.run_completion_meta,
        }
        handler = dispatch.get(kind)
        return handler(value) if handler is not None else ""

    def job_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one job completion."""
        if self.db is None:
            return ""
        try:
            row = self.db.job(int(value))
        except ValueError:
            return ""
        if row is None:
            return ""
        artifacts = self.db.artifact_counts_by_job().get(str(row["id"]), 0)
        return f"serial={row['serial']} status={row['status']} artifacts={artifacts} command={row['command_line']}"

    def run_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one run completion."""
        if self.db is None:
            return ""
        try:
            serial = self.db.resolve_run_serial(value)
        except ValueError:
            return ""
        artifacts = self.db.artifact_counts_by_run().get(serial, 0)
        for row in self.db.runs(active_only=False):
            if row["command_run_id"] == serial:
                return f"serial={serial} source={row['source']} artifacts={artifacts} events={row['events']}"
        return ""

    def pipeline_completion_meta(self, value: str) -> str:
        """Return prompt metadata for one pipeline completion."""
        if self.db is None:
            return ""
        try:
            serial = self.db.resolve_pipeline_serial(value)
        except ValueError:
            return ""
        artifacts = self.db.artifact_counts_by_pipeline().get(serial, 0)
        for row in self.db.pipelines(active_only=False):
            if row["pipeline_id"] == serial:
                return f"serial={serial} artifacts={artifacts} runs={row['runs']} events={row['events']}"
        return ""
