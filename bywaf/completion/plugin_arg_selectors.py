"""Framework selector completion for plugin commandlets.

Used by: `PluginArgumentCompletionMixin` to complete `--from` selectors without
mixing framework replay-selector rules into plugin-owned option completion.
"""

from __future__ import annotations

from collections.abc import Callable

from ..specs import CompletionSpec

CompleteBySpec = Callable[[CompletionSpec, str], list[str]]

FROM_SELECTORS = (("job=", "job"), ("pipeline=", "pipeline"), ("step=", "step"), ("topic=", "topic"))
FROM_SELECTOR_KEYS = {"job", "pipeline", "step", "topic"}


def framework_from_selector_candidates(complete_by_spec: CompleteBySpec, prefix: str) -> list[str]:
    """Complete selector values used after a plugin commandlet `--from` token."""
    for selector, spec_kind in FROM_SELECTORS:
        if prefix.startswith(selector):
            value_prefix = prefix.split("=", 1)[1]
            return [f"{selector}{value}" for value in complete_by_spec(CompletionSpec(spec_kind), value_prefix)]
    return [selector for selector, _spec_kind in FROM_SELECTORS if selector.startswith(prefix)]


def in_from_selector_context(args: list[str], prefix: str) -> bool:
    """Return whether the current token belongs to framework `--from` selectors."""
    if "--from" not in args:
        return False
    if prefix and not any(selector.startswith(prefix) or prefix.startswith(selector) for selector, _kind in FROM_SELECTORS):
        return False
    from_index = args.index("--from")
    following = args[from_index + 1 :]
    if prefix and following and following[-1] == prefix:
        following = following[:-1]
    if not following:
        return True
    return all(is_from_selector_token(token) for token in following)


def is_from_selector_token(token: str) -> bool:
    """Return whether one token is a complete `--from` selector assignment."""
    key, separator, value = token.partition("=")
    return bool(separator and value and key in FROM_SELECTOR_KEYS)
