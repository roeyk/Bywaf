"""Output, progress, and paging helpers for CommandContext."""

# pyright: reportAttributeAccessIssue=false, reportArgumentType=false

from __future__ import annotations

import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ...event import Event
from ...rendering import Column, Table
from ..services import progress_payload, should_emit_progress


class ContextOutputMixin:
    """Mixin that provides framework output/progress request methods."""

    def output(self, text: object = "", *, end: str = "\n") -> None:
        """Request normal command output from the framework console."""
        payload = {
            "text": str(text),
            "end": end,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.output.requested", payload) is None:
            print(str(text), end=end, flush=True)

    def table(
        self,
        rows: Iterable[Mapping[str, object] | Sequence[object]],
        columns: Sequence[str | Column] | None = None,
        *,
        title: str | None = None,
    ) -> None:
        """Render a structured table through the framework output path."""
        self.render.table(Table.from_rows(rows, columns, title=title))

    def alert(self, message: str, *, level: str = "alert", silent: bool = False) -> None:
        """Request a framework-owned console alert."""
        payload = {
            "message": message,
            "level": level,
            "silent": silent,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.alert.requested", payload) is None and not silent:
            print(f"{self.source} <{self.command_run_id or 'interactive'}>: {message}", flush=True)

    def progress_started(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-started event."""
        return self.progress(
            status="started",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress(
        self,
        *,
        phase: str,
        status: str = "updated",
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit a structured progress event subject to framework throttling."""
        payload = progress_payload(
            self,
            status=status,
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            extra=extra,
        )
        return self.publish_progress_payload(payload)

    def progress_completed(
        self,
        *,
        phase: str,
        current: int | float | None = None,
        total: int | float | None = None,
        unit: str | None = None,
        message: str | None = None,
        target: str | None = None,
        eta_seconds: int | float | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-completed event."""
        return self.progress(
            status="completed",
            phase=phase,
            current=current,
            total=total,
            unit=unit,
            message=message,
            target=target,
            eta_seconds=eta_seconds,
            **extra,
        )

    def progress_failed(
        self,
        *,
        phase: str,
        message: str | None = None,
        error: str | None = None,
        **extra: object,
    ) -> Event | None:
        """Emit an unthrottled structured progress-failed event."""
        payload_extra = dict(extra)
        if error is not None:
            payload_extra["error"] = error
        payload = progress_payload(
            self,
            status="failed",
            phase=phase,
            current=None,
            total=None,
            unit=None,
            message=message,
            target=None,
            eta_seconds=None,
            extra=payload_extra,
        )
        return self.publish_progress_payload(payload)

    def publish_progress_payload(self, payload: Mapping[str, object]) -> Event | None:
        """Publish one progress payload after applying throttle policy."""
        if not should_emit_progress(self, payload):
            return None
        if self._db is None:
            return None
        status = str(payload.get("status", "updated"))
        self.audit_capability("plugin.progress")
        event = self._db.publish(
            f"plugin.progress.{status}",
            dict(payload),
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        self.metadata["_progress_last"] = {
            "monotonic": time.monotonic(),
            "phase": payload.get("phase"),
            "percent": payload.get("percent"),
            "status": status,
        }
        return event

    def page_file(self, path: str | Path) -> None:
        """Request framework-owned file paging for terminal and GUI frontends."""
        file_path = Path(path).expanduser()
        payload = {
            "path": str(file_path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
        }
        if self.request("framework.file.page.requested", payload) is None:
            print(file_path.read_text(errors="replace"), end="", flush=True)

    def page_text(self, text: object, *, suffix: str = ".txt") -> None:
        """Page generated text through the same framework path as local files."""
        content = str(text)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as handle:
            handle.write(content)
            if content and not content.endswith("\n"):
                handle.write("\n")
            path = Path(handle.name)
        payload = {
            "path": str(path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
            "temporary": True,
        }
        if self.request("framework.file.page.requested", payload) is None:
            try:
                print(path.read_text(errors="replace"), end="", flush=True)
            finally:
                path.unlink(missing_ok=True)
