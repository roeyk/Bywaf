"""Source analysis helpers for plugin checking.

Provides lightweight AST inference for capabilities and risky direct API use in
filesystem plugins.

Used by:
- scripts/plugin_check.py: report inferred capabilities and evidence.
- tests: exercise plugin author tooling without running plugin code."""

from __future__ import annotations

import ast
from pathlib import Path

from bywaf.tools.plugin_check_model import CapabilityEvidence, SourceAnalysis, SourceDiagnostic
from bywaf.tools.plugin_check_visitor import CapabilityVisitor


def analyze_plugin_source(plugin_dir: Path) -> SourceAnalysis:
    """Infer likely capabilities from Python source without importing it.

    This is deliberately static.  The checker should be safe to run on a plugin
    with missing dependencies or risky import-time side effects, while still
    giving authors and LLMs concrete feedback before Bywaf imports plugin.py.
    """
    evidence: list[CapabilityEvidence] = []
    warnings: list[CapabilityEvidence] = []
    diagnostics: list[SourceDiagnostic] = []
    inferred_emits: set[str] = set()
    paths = [plugin_dir] if plugin_dir.is_file() else sorted(plugin_dir.rglob("*.py"))
    for path in paths:
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        visitor = CapabilityVisitor(path=path, source=source)
        visitor.visit(tree)
        evidence.extend(visitor.evidence)
        warnings.extend(visitor.warnings)
        diagnostics.extend(visitor.diagnostics)
        inferred_emits.update(visitor.inferred_emits)
    capabilities = sorted({item.capability for item in evidence})
    return SourceAnalysis(
        tuple(capabilities),
        tuple(sorted(inferred_emits)),
        tuple(evidence),
        tuple(warnings),
        tuple(diagnostics),
    )
