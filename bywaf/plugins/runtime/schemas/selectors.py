"""Selector parsing for the schemas command.

Used by: `runtime.schemas.Schemas` to keep command-line selector validation
separate from schema collection and rendering.
"""

from __future__ import annotations


# Default selector values consumed by `parse_schema_args()`.
DEFAULT_SCHEMA_SELECTORS = {
    "owner": "all",
    "topic": "",
    "detail": "false",
    "sort": "topic",
}

# Completion candidates consumed by `schema_completions()`.
SCHEMA_COMPLETIONS = (
    "--page",
    "detail=false",
    "detail=true",
    "owner=all",
    "owner=framework",
    "owner=plugin",
    "sort=owner",
    "sort=-owner",
    "sort=topic",
    "sort=-topic",
    "sort=used",
    "sort=-used",
    "topic=",
)


def parse_schema_args(args: list[str]) -> tuple[dict[str, str], bool]:
    """Parse `schemas` command selectors and page flag.

    Called by: `Schemas.run()` before rows are selected and rendered.
    """
    selectors = dict(DEFAULT_SCHEMA_SELECTORS)
    page = False
    for arg in args:
        if arg == "--page":
            page = True
            continue
        key, separator, value = arg.partition("=")
        if not separator:
            raise ValueError("schemas selectors must be key=value")
        validate_selector(key, value)
        selectors[key] = value
    return selectors, page


def schema_completions(prefix: str) -> list[str]:
    """Return selector completions for the current prefix."""
    return [candidate for candidate in SCHEMA_COMPLETIONS if candidate.startswith(prefix)]


def validate_selector(key: str, value: str) -> None:
    """Raise a user-facing error for invalid `schemas` selectors."""
    if key not in DEFAULT_SCHEMA_SELECTORS:
        raise ValueError("schemas selectors must be one of: detail, owner, sort, topic")
    if key == "owner" and value not in {"all", "framework", "plugin"}:
        raise ValueError("schemas owner= must be one of: all, framework, plugin")
    if key == "detail" and value not in {"false", "true"}:
        raise ValueError("schemas detail= must be one of: false, true")
    if key == "sort" and value.lstrip("-") not in {"owner", "topic", "used"}:
        raise ValueError("schemas sort= must be one of: owner, topic, used")
