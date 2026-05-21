"""Public specification dataclasses for plugin declarations."""

from .command import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from .plan import PlanItem, PlanRepair, PlanReport
from .trigger import TriggerSpec

__all__ = [
    "ArgumentSpec",
    "CommandSpec",
    "CompletionSpec",
    "OptionSpec",
    "PlanItem",
    "PlanRepair",
    "PlanReport",
    "TriggerSpec",
]
