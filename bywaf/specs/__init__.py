"""Specification package exports.

Provides the stable import surface for command, trigger, and plan metadata
classes used by plugins and framework components."""


from .command import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from .plan import PlanItem, PlanRepair, PlanReport
from .trigger import TriggerSpec

# Public metadata dataclasses that plugin authors may import directly.
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
