"""Data models for plugin source analysis reports.

Used by:
- `plugin_check` diagnostics, LLM feedback output, CI checks, and external
  plugin author workflows.
- tests that lock down plugin authoring contracts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """One source-code observation that implies or warns about a capability."""

    capability: str
    kind: str
    path: str
    line: int
    detail: str
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable evidence record."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceDiagnostic:
    """One plugin-authoring diagnostic suitable for LLM feedback."""

    severity: str
    code: str
    path: str
    line: int
    message: str
    guidance: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable diagnostic record."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceAnalysis:
    """Capability inference result for one plugin source tree."""

    inferred_capabilities: tuple[str, ...]
    inferred_emits: tuple[str, ...]
    evidence: tuple[CapabilityEvidence, ...]
    warnings: tuple[CapabilityEvidence, ...]
    diagnostics: tuple[SourceDiagnostic, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable analysis result."""
        return {
            "inferred_capabilities": list(self.inferred_capabilities),
            "inferred_emits": list(self.inferred_emits),
            "evidence": [item.to_dict() for item in self.evidence],
            "warnings": [item.to_dict() for item in self.warnings],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }
