"""Plugin manifest trigger section parser."""

from __future__ import annotations

from typing import Any

from bywaf.specs import TriggerSpec

from .manifest_fields import bool_field, optional_string_field, string_field, string_list_field


def parse_trigger_rows(value: Any, source: str) -> tuple[TriggerSpec, ...]:
    """Parse optional [[triggers]] manifest entries.

    Trigger rows are provider-owned automation rules.  They are parsed from the
    manifest so the registry can list and validate trigger behavior without
    trusting arbitrary top-level plugin code first.
    """
    if value in (None, []):
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{source} triggers must be a list")
    triggers: list[TriggerSpec] = []
    names: set[str] = set()
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"{source} triggers entry {index} must be a table")
        name = string_field(row, "name", source, f"triggers entry {index}")
        if name in names:
            raise ValueError(f"{source} duplicate trigger: {name}")
        names.add(name)
        topic = string_field(row, "topic", source, f"triggers entry {index}")
        action_command = string_field(row, "action_command", source, f"triggers entry {index}")
        action_mode = optional_string_field(row, "action_mode", source, f"triggers entry {index}", default="service")
        assert action_mode is not None
        if action_mode not in {"foreground", "background", "service"}:
            raise ValueError(f"{source} triggers entry {index} action_mode must be foreground, background, or service")
        payload_equals = row.get("payload_equals", {})
        # Keep manifest predicates simple and deterministic.  Complex matching
        # belongs in explicit commandlets; trigger metadata should remain
        # inspectable without importing plugin code.
        if not isinstance(payload_equals, dict):
            raise ValueError(f"{source} triggers entry {index} payload_equals must be a table")
        for key, item in payload_equals.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{source} triggers entry {index} payload_equals keys must be strings")
            if not isinstance(item, str):
                raise ValueError(f"{source} triggers entry {index} payload_equals values must be strings")
        suppress_self_trigger = row.get("suppress_self_trigger", True)
        if not isinstance(suppress_self_trigger, bool):
            raise ValueError(f"{source} triggers entry {index} suppress_self_trigger must be true or false")
        description = optional_string_field(row, "description", source, f"triggers entry {index}", default="")
        capability = optional_string_field(row, "capability", source, f"triggers entry {index}")
        triggers.append(
            TriggerSpec(
                name=name,
                topic=topic,
                action_command=action_command,
                description=description or "",
                action_mode=action_mode,
                capability=capability,
                payload_equals=tuple(sorted(payload_equals.items())),
                active_job=bool_field(row, "active_job", source, f"triggers entry {index}"),
                exclude_commandlets=string_list_field(row, "exclude_commandlets", source, f"triggers entry {index}"),
                suppress_self_trigger=suppress_self_trigger,
            )
        )
    return tuple(triggers)
