"""Resource and path completion helpers.

Provides load/save resource expression completion and at-file path completion.
Used by the completion engine and readline/prompt-toolkit adapter facade.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Settings
from ..utils import complete_path

DEFAULT_SETTINGS = Settings()
PLUGIN_ROOT_SHORTCUTS = (
    "./",
    "./.bywaf/plugins/",
    "~/.bywaf/plugins/",
    "/usr/local/share/bywaf/plugins/",
    "/usr/share/bywaf/plugins/",
)


def resource_candidates(prefix: str, keywords: tuple[str, ...]) -> list[str]:
    """Complete key=value resource expressions used by load/save."""
    for keyword in keywords:
        if keyword.endswith("=") and prefix.startswith(keyword):
            value = prefix.split("=", 1)[1]
            return [f"{keyword}{path}" for path in complete_resource_value(keyword[:-1], value)]
    keyword_matches = [keyword for keyword in keywords if keyword.startswith(prefix)]
    if keyword_matches:
        return keyword_matches
    if prefix:
        return complete_path(prefix)
    return list(keywords)


def complete_at_file_prefix(prefix: str) -> list[str]:
    """Complete framework at-file path prefixes while preserving operators."""
    if prefix.startswith("@@"):
        value = prefix[2:]
        return [f"@@{candidate}" for candidate in complete_path(value)]
    for operator in ("@lines:", "@raw:"):
        if prefix.startswith(operator):
            value = prefix.removeprefix(operator)
            return [f"{operator}{candidate}" for candidate in complete_path(value)]
    value = prefix.removeprefix("@")
    return [f"@{candidate}" for candidate in complete_path(value)]


def complete_resource_value(kind: str, value: str) -> list[str]:
    """Complete the value side of a load/save resource expression."""
    root_shortcuts: list[str] = []
    if kind == "plugin":
        root_shortcuts = plugin_root_shortcut_candidates(value)
        if root_shortcuts and value:
            return root_shortcuts
    if is_explicit_path(value):
        return preserve_explicit_prefix(value, complete_path(value or "."))
    if kind == "plugin":
        candidates = complete_path(value, DEFAULT_SETTINGS.plugin_dir)
        if not value:
            candidates.extend(root_shortcuts)
            candidates.extend(local_plugin_directory_candidates())
        return sorted(dict.fromkeys(candidates))
    return complete_path(value)


def local_plugin_directory_candidates() -> list[str]:
    """Return explicit local plugin directory candidates for `plugin load=`."""
    candidates: list[str] = []
    for child in Path(".").iterdir():
        if not child.is_dir():
            continue
        if (child / "plugin.py").exists() or (child / "bywaf.plugin.toml").exists():
            candidates.append(f"./{child.name}/")
    return sorted(candidates)


def plugin_root_shortcut_candidates(value: str) -> list[str]:
    """Return memorable plugin-root shortcuts matching the current value."""
    if not value:
        return list(PLUGIN_ROOT_SHORTCUTS)
    return [shortcut for shortcut in PLUGIN_ROOT_SHORTCUTS if shortcut.startswith(value)]


def is_explicit_path(value: str) -> bool:
    """Return True when a resource value should be treated as a path."""
    return value.startswith(("./", "../", "~/", "/"))


def preserve_explicit_prefix(value: str, candidates: list[str]) -> list[str]:
    """Keep leading `./` visible so readline replaces the token correctly."""
    if value.startswith("./"):
        return [candidate if candidate.startswith("./") else f"./{candidate}" for candidate in candidates]
    return candidates
