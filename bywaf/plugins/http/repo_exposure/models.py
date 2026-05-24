"""Domain models for repository exposure checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DetectionStatus(Enum):
    """Detection result vocabulary for source repository exposure checks."""

    SAFE = "safe"
    CANDIDATE = "candidate"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class GitConfigProbeResult:
    """Result from probing one endpoint for `/.git/config`."""

    base_url: str
    checked_url: str
    host: str
    port: int
    scheme: str
    status: DetectionStatus
    http_status: int | None = None
    final_url: str = ""
    elapsed_ms: int = 0
    evidence: str = ""
    error: str = ""
