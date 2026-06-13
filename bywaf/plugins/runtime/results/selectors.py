"""Selector parsing for the runtime results command.

Used by: `runtime.results.Results.run()` before selecting a result scope.
"""

from __future__ import annotations

from argparse import Namespace

from bywaf.plugins.network.portscanner.ports import PORT_SORT_KEYS
from bywaf.runtime.display import parse_runtime_sort


RESULT_SCOPE_KEYS = {"all", "interval", "job", "once", "pipeline", "step", "sort"}
"""Selector keys accepted by the runtime results command."""


def parse_results_selectors(tokens: list[str]) -> Namespace:
    """Parse `results` selector tokens into a single runtime scope.

    Called by: `Results.run()` after argparse has stripped framework-style
    flags such as `--follow` and `--page`.
    """
    scope: dict[str, str] = {}
    sort_key = "host"
    interval = 1.0
    once = False
    for token in tokens:
        # Results intentionally use key=value selectors rather than argparse
        # flags so scope syntax matches job/pipeline/step/report commands.
        if token.startswith("--"):
            raise ValueError(f"results uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("results selectors must be key=value")
        if key not in RESULT_SCOPE_KEYS:
            raise ValueError("results selectors must be one of: all, job, pipeline, step, sort")
        if key == "interval":
            interval = parse_results_interval(value)
        elif key == "once":
            once = parse_results_boolean(value, "once")
        elif key == "sort":
            sort_key = parse_runtime_sort(value, PORT_SORT_KEYS, "results")
        else:
            # Scope selectors are validated together below so ambiguous
            # combinations produce one consistent error path.
            scope[key] = value
    validate_results_scope(scope)
    return Namespace(scope=scope, sort=sort_key, interval=interval, once=once)


def parse_results_interval(raw: str) -> float:
    """Parse follow polling interval seconds.

    Called by: `parse_results_selectors()` for `interval=`.
    """
    try:
        interval = float(raw)
    except ValueError as exc:
        raise ValueError(f"invalid results interval= value: {raw}") from exc
    if interval <= 0:
        raise ValueError("results interval= must be greater than 0")
    return interval


def parse_results_boolean(raw: str, key: str) -> bool:
    """Parse true/false selector values.

    Called by: `parse_results_selectors()` for boolean selector fields.
    """
    value = raw.casefold()
    if value in {"true", "yes", "1", "on"}:
        return True
    if value in {"false", "no", "0", "off"}:
        return False
    raise ValueError(f"results {key}= must be true or false")


def validate_results_scope(scope: dict[str, str]) -> None:
    """Reject ambiguous result scopes.

    Called by: `parse_results_selectors()` after collecting selector values.
    """
    all_value = scope.get("all", "false")
    if all_value not in {"true", "false"}:
        raise ValueError("results all= must be true or false")
    explicit_scopes = [key for key in ("job", "pipeline", "step") if key in scope]
    # Results can render the latest productive scope, all events, or one
    # explicit runtime entity. Mixing these would make follow behavior unclear.
    if all_value == "true" and explicit_scopes:
        raise ValueError("results all=true cannot be combined with job=, pipeline=, or step=")
    if len(explicit_scopes) > 1:
        raise ValueError("results accepts only one runtime scope: job=, pipeline=, or step=")
