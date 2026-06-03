"""Result models for framework-mediated process execution."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Normalized result from a framework-mediated process run."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    request_event_id: int | None = None

    @property
    def ok(self) -> bool:
        """Return whether the process exited successfully."""
        return self.returncode == 0

    def check_returncode(self) -> None:
        """Raise `CalledProcessError` when the process failed."""
        if self.returncode != 0:
            raise subprocess.CalledProcessError(
                self.returncode,
                list(self.argv),
                output=self.stdout,
                stderr=self.stderr,
            )
