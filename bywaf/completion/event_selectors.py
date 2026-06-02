"""Runtime event selector completion helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..specs import CompletionSpec

if TYPE_CHECKING:
    from .builtins import BuiltinCompletionMixin


EVENT_SELECTORS = ("job=", "step=", "pipeline=", "serial=", "topic=")
EVENT_SELECTOR_COMPLETION_KINDS = {
    "job": "job",
    "pipeline": "pipeline",
    "serial": "serial",
    "step": "step",
    "topic": "topic",
}


def event_candidates(completer: "BuiltinCompletionMixin", prefix: str) -> list[str]:
    """Complete `event` selectors and selector values."""
    if prefix.isdigit():
        if not completer.db:
            return []
        return [str(event.id) for event in completer.db.recent_events(50) if str(event.id).startswith(prefix)]
    selector_values = event_selector_value_candidates(completer, prefix)
    if selector_values is not None:
        return selector_values
    if prefix:
        selector_matches = [selector for selector in EVENT_SELECTORS if selector.startswith(prefix)]
        if selector_matches:
            return selector_matches
    return [*completer.topic_candidates(), *EVENT_SELECTORS]


def event_selector_value_candidates(completer: "BuiltinCompletionMixin", prefix: str) -> list[str] | None:
    """Complete selector values after `event <selector>=`."""
    for selector in EVENT_SELECTORS:
        if not prefix.startswith(selector):
            continue
        value_prefix = prefix.split("=", 1)[1]
        kind = EVENT_SELECTOR_COMPLETION_KINDS[selector[:-1]]
        return [
            f"{selector}{value}"
            for value in completer.complete_by_spec(CompletionSpec(kind), value_prefix)
        ]
    return None
