"""Version compatibility helpers for plugin metadata.

Provides the small SemVer-like comparison support needed for plugin
`requires_bywaf` metadata without taking a package-management dependency.

Used by:
- registry.manifest: validate requirement syntax.
- plugin tooling: reject incompatible plugin/framework combinations."""

from __future__ import annotations

import re


REQUIREMENT_RE = re.compile(r"^(>=|>|<=|<|==)?\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def parse_version_tuple(value: str) -> tuple[int, int, int]:
    """Return the numeric major/minor/patch tuple from a SemVer-like string."""
    core = value.split("-", 1)[0].split("+", 1)[0]
    major, minor, patch = core.split(".", 2)
    return (int(major), int(minor), int(patch))


def satisfies_bywaf_requirement(current: str, requirement: str | None) -> bool:
    """Return whether the current Bywaf version satisfies one simple clause."""
    if not requirement:
        return True
    match = REQUIREMENT_RE.match(requirement.strip())
    if match is None:
        return False
    operator = match.group(1) or ">="
    expected = parse_version_tuple(match.group(2))
    observed = parse_version_tuple(current)
    if operator == ">=":
        return observed >= expected
    if operator == ">":
        return observed > expected
    if operator == "<=":
        return observed <= expected
    if operator == "<":
        return observed < expected
    return observed == expected
