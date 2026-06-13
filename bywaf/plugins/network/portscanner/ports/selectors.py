"""Selector parsing for the `ports` result-view commandlet.

Used by: `ports.Ports.run()` before event selection, and `Ports.complete()`
for the list of supported selector keys.
"""

from __future__ import annotations

from argparse import Namespace

from bywaf.event.filters import parse_payload_filter_tokens
from bywaf.runtime.display import parse_runtime_sort

PORT_SORT_KEYS = ("host", "port", "protocol", "service", "reason", "event", "time")
PORT_FILTER_KEYS = {"host", "port", "protocol", "service", "reason", "state"}
PORT_SCOPE_KEYS = {"all", "job", "pipeline", "step"}


def parse_ports_selectors(tokens: list[str], *, last: bool = False, new: bool = False) -> Namespace:
    """Parse `ports` selector tokens into scope, filters, and sort order.

    Called by: `ports.Ports.run()` after argparse handles binary flags such as
    `--last`, `--new`, and `--page`.
    """
    scope: dict[str, str] = {}
    filters: list[str] = []
    sort_key = "host"
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"ports uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("ports selectors must be key=value")
        if key == "sort":
            sort_key = parse_runtime_sort(value, PORT_SORT_KEYS, "ports")
        elif key in PORT_SCOPE_KEYS:
            scope[key] = value
        elif key in PORT_FILTER_KEYS:
            filters.append(token)
        else:
            raise ValueError(
                "ports selectors must be one of: all, job, pipeline, step, host, port, protocol, service, reason, state, sort"
            )
    validate_ports_scope(scope)
    if last and new:
        raise ValueError("ports accepts only one of --last or --new")
    if (last or new) and scope.get("all") == "true":
        raise ValueError("ports all=true cannot be combined with --last or --new")
    return Namespace(scope=scope, filters=parse_payload_filter_tokens(filters), sort=sort_key, last=last, new=new)


def validate_ports_scope(scope: dict[str, str]) -> None:
    """Reject ambiguous `ports` scope combinations."""
    all_value = scope.get("all", "false")
    if all_value not in {"true", "false"}:
        raise ValueError("ports all= must be true or false")
    explicit_scopes = [key for key in ("job", "pipeline", "step") if key in scope]
    if all_value == "true" and explicit_scopes:
        raise ValueError("ports all=true cannot be combined with job=, pipeline=, or step=")
    if len(explicit_scopes) > 1:
        raise ValueError("ports accepts only one runtime scope: job=, pipeline=, or step=")


__all__ = ["PORT_FILTER_KEYS", "PORT_SCOPE_KEYS", "PORT_SORT_KEYS", "parse_ports_selectors", "validate_ports_scope"]
