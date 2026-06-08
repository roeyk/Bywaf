"""Shared state helpers for plugin source checking."""

from __future__ import annotations

import ast
from pathlib import Path

from bywaf.tools.plugin_check_model import CapabilityEvidence, SourceDiagnostic


class CapabilityAnalysisState:
    """State and source-location helpers for plugin source analysis."""

    def init_analysis_state(self, *, path: Path, source: str) -> None:
        """Initialize mutable source-analysis state."""
        self.path = path
        self.source = source
        self.aliases: dict[str, str] = {}
        self.evidence: list[CapabilityEvidence] = []
        self.warnings: list[CapabilityEvidence] = []
        self.diagnostics: list[SourceDiagnostic] = []

    def add_evidence(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str = "high",
    ) -> None:
        """Append one inferred capability evidence record."""
        self.evidence.append(self.make_record(capability, kind, node, detail, confidence=confidence))

    def add_warning(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str = "high",
    ) -> None:
        """Append one advisory warning record."""
        self.warnings.append(self.make_record(capability, kind, node, detail, confidence=confidence))

    def add_diagnostic(
        self,
        severity: str,
        code: str,
        node: ast.AST,
        message: str,
        guidance: str,
    ) -> None:
        """Append one plugin-authoring diagnostic."""
        self.diagnostics.append(
            SourceDiagnostic(
                severity=severity,
                code=code,
                path=str(self.path),
                line=getattr(node, "lineno", 0),
                message=message,
                guidance=guidance,
            )
        )

    def make_record(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str,
    ) -> CapabilityEvidence:
        """Build an evidence record with source location."""
        segment = ast.get_source_segment(self.source, node)
        if segment:
            detail = segment.strip().splitlines()[0]
        return CapabilityEvidence(
            capability=capability,
            kind=kind,
            path=str(self.path),
            line=getattr(node, "lineno", 0),
            detail=detail,
            confidence=confidence,
        )

    def call_path(self, node: ast.AST) -> str:
        """Return a dotted call path, with simple import aliases resolved."""
        path = self.attribute_path(node)
        if not path:
            return ""
        parts = path.split(".")
        if parts[0] in self.aliases:
            resolved = self.aliases[parts[0]]
            return ".".join((resolved, *parts[1:]))
        return path

    def attribute_path(self, node: ast.AST) -> str:
        """Return a dotted attribute/name path for a simple expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self.attribute_path(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self.attribute_path(node.func)
        return ""
