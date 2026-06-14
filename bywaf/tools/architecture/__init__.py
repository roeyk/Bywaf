"""Lightweight architecture metrics for Bywaf source and documentation.

Provides import dependency, size, fan-in/fan-out, complexity, test-reference,
churn, security-surface, cycle, and documentation pressure metrics without
requiring optional analysis dependencies.

Used by:
- maintainers: spot coupling pressure before refactors.
- release checks: compare module size and dependency drift over time.

Public surface: exports the collector, CLI, formatting helpers, graph helpers,
and source metric primitives that tests and maintainer scripts use directly.
"""

from __future__ import annotations

from .cli import main as main
from .collector import collect_architecture_metrics as collect_architecture_metrics
from .collector import dependency_cycles as dependency_cycles
from .formatting import format_documentation_impact as format_documentation_impact
from .formatting import format_metrics as format_metrics
from .graph import is_type_checking_guard as is_type_checking_guard
from .graph import normalize_absolute_import as normalize_absolute_import
from .graph import resolve_relative_import as resolve_relative_import
from .graph import runtime_import_nodes as runtime_import_nodes
from .models import ArchitectureMetrics as ArchitectureMetrics
from .models import ModuleMetric as ModuleMetric
from .models import ModuleStaticStats as ModuleStaticStats
from .source import SECURITY_SURFACE_TOKENS as SECURITY_SURFACE_TOKENS
from .source import ast_docstring_lines as ast_docstring_lines
from .source import complexity_score as complexity_score
from .source import dense_construct_score as dense_construct_score
from .source import documentation_pressure_score as documentation_pressure_score
from .source import security_surface_hits as security_surface_hits
from .source import source_comment_lines as source_comment_lines
