"""Trigger declaration specs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TriggerSpec:
    """Provider-owned ON event DO command rule consumed by the framework."""

    name: str
    topic: str
    action_command: str
    description: str = ""
    action_mode: str = "service"
    capability: str | None = None
    payload_equals: tuple[tuple[str, str], ...] = ()
    active_job: bool = False
    exclude_commandlets: tuple[str, ...] = ()
    suppress_self_trigger: bool = True
