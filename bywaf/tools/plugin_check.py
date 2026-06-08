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
    has_plugin_factory = False
    has_plugins_factory = False
    commandlet_decorator_nodes: list[tuple[Path, ast.AST]] = []
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
        has_plugin_factory = has_plugin_factory or visitor.has_plugin_factory
        has_plugins_factory = has_plugins_factory or visitor.has_plugins_factory
        commandlet_decorator_nodes.extend((path, node) for node in visitor.commandlet_decorator_nodes)
    if commandlet_decorator_nodes and not has_plugin_factory and not has_plugins_factory:
        path, node = commandlet_decorator_nodes[0]
        diagnostics.append(
            SourceDiagnostic(
                severity="error",
                code="missing-plugin-factory",
                path=str(path),
                line=getattr(node, "lineno", 1),
                message="module defines @commandlet objects but no plugin() or plugins() factory",
                guidance=(
                    "Add an undecorated factory at module scope, for example: "
                    "def plugin() -> Commandlet: return your_commandlet. "
                    "Do not call the decorated FunctionCommandlet directly in tests; use plugin().run(...)."
                ),
            )
        )
    capabilities = sorted({item.capability for item in evidence})
    return SourceAnalysis(
        tuple(capabilities),
        tuple(sorted(inferred_emits)),
        tuple(evidence),
        tuple(warnings),
        tuple(diagnostics),
    )
