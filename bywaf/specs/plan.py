"""Plan/policy specification dataclasses.

Provides structured planning and policy metadata used when commandlets or tools
need to describe intended actions before execution.

Used by:
- plugins and future policy flows: represent proposed work consistently.
- tests and docs: validate the public shape of plan data."""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class PlanItem:
    """One structured item in a pre-run plan."""

    kind: str
    value: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PlanRepair:
    """A suggested per-run repair for a plan warning."""

    # Repairs patch the current invocation's args. They must not mutate saved
    # variables, source files, or command history.
    name: str
    description: str
    patched_args: tuple[str, ...]
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PlanReport:
    """Structured description of a commandlet's intended action."""

    # requires_confirmation is separate from warnings so harmless previews can
    # still display warnings without forcing approval in every code path.
    action: str
    summary: str
    items: tuple[PlanItem, ...] = ()
    warnings: tuple[str, ...] = ()
    repairs: tuple[PlanRepair, ...] = ()
    requires_confirmation: bool = False
