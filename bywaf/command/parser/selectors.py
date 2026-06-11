"""Framework selector parsing helpers for command text.

These helpers peel Bywaf-owned selectors away from plugin-owned argv tokens so
plugin commandlets only see their own arguments.

Used by:
- `command.parser.parse_invocation()`: removes final text selectors, replay
  selectors, approval/test flags, and shell background markers.
- parser tests: indirectly verify these helpers through public pipeline and
  invocation parsing.
"""

from __future__ import annotations

from typing import TypeAlias

from ..pipeline_syntax import normalize_final_text


Selectors: TypeAlias = dict[str, str | None]

COMMANDLET_TEXT_SELECTORS = {
    "artifact": frozenset({"name", "note"}),
    "bundle": frozenset({"name"}),
    "key": frozenset({"name"}),
    "report": frozenset({"name", "note"}),
    "search": frozenset({"name", "note"}),
}

CONTEXT_SELECTOR_KEYS = {
    "pipeline": "from_pipeline",
    "job": "from_job",
    "step": "from_step",
    "topic": "from_topic",
}

CONTEXT_SELECTOR_BOOL_FLAGS = {
    "--test": ("plan_only", "true"),
    "--yes": ("approved", "true"),
}


def commandlet_owns_text_selector(commandlet: str | None, key: str) -> bool:
    """Return whether a commandlet owns a selector-like argument.

    Called by: `parse_invocation()` before it peels framework text selectors.
    This prevents the framework parser from consuming valid plugin arguments
    such as `report defer 1 note=...` before the commandlet has a chance to
    parse them.
    """
    if commandlet is None:
        return False
    return key in COMMANDLET_TEXT_SELECTORS.get(commandlet, frozenset())


def peel_background_marker(tokens: list[str]) -> tuple[list[str], bool]:
    """Remove a trailing shell-style `&` marker from a token list."""
    last = tokens[-1]
    if last == "&":
        return tokens[:-1], True
    if last.endswith("&"):
        stripped = last[:-1]
        if stripped:
            return [*tokens[:-1], stripped], True
        return tokens[:-1], True
    return tokens, False


def peel_final_text_selector(text: str, key: str) -> tuple[str, str | None]:
    """Remove a framework-owned final text selector from raw stage text.

    The selector is parsed before `shlex.split` so a final unquoted note can
    consume the rest of the command stage:

    `hostscanner targets note=client approved`
    """
    index = find_unquoted_text_selector(text, key)
    if index is None:
        return text, None
    value = normalize_final_text(text[index + len(key) + 1:])
    if not value:
        raise ValueError(f"{key}= requires a value")
    return text[:index].rstrip(), value


def find_unquoted_text_selector(text: str, key: str) -> int | None:
    """Return the index of a token-boundary text selector outside shell quotes."""
    quote: str | None = None
    escaped = False
    needle = f"{key}="
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if text.startswith(needle, index) and (index == 0 or text[index - 1].isspace()):
            return index
    return None


def peel_context_selectors(args: list[str]) -> tuple[list[str], dict[str, str | None]]:
    """Remove framework-owned selector flags from plugin arguments.

    Called by: `parse_invocation()` after shell splitting.  The return value is
    the plugin-owned argv plus framework execution selectors used later by
    runner/context code.
    """
    selectors = default_context_selectors()
    cleaned: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--from":
            # `--from` owns the following selector assignments until the first
            # non-selector token. Everything after that belongs back to the
            # plugin commandlet.
            index = peel_from_group(args, index + 1, selectors)
            continue

        if apply_bool_selector(token, selectors):
            index += 1
            continue

        cleaned.append(token)
        index += 1
    return cleaned, selectors


def default_context_selectors() -> Selectors:
    """Return the framework selector defaults used for every commandlet.

    Called by: `peel_context_selectors()` before scanning argv tokens.  Booleans
    are represented as strings because the parser later maps this dictionary
    directly onto `CommandInvocation` fields with existing string comparisons.
    """
    return {
        "from_step": None,
        "from_pipeline": None,
        "from_job": None,
        "from_topic": None,
        "plan_only": "false",
        "approved": "false",
    }


def peel_from_group(args: list[str], start: int, selectors: Selectors) -> int:
    """Consume the selector assignment group after a `--from` token.

    Returns the index of the first token not consumed by the group.  `topic=`
    is only a narrowing selector, so it must accompany at least one replay
    source: `job=`, `pipeline=`, or `step=`.
    """
    index = start
    seen: set[str] = set()
    while index < len(args):
        key, value = context_selector_assignment(args[index])
        if key is None:
            break
        selectors[key] = value
        seen.add(key)
        index += 1
    require_replay_source(seen)
    return index


def require_replay_source(seen: set[str]) -> None:
    """Validate that a `--from` group names a real replay source."""
    if not seen:
        raise ValueError("--from requires job=, pipeline=, or step=")
    if seen.isdisjoint({"from_job", "from_pipeline", "from_step"}):
        raise ValueError("--from requires job=, pipeline=, or step=; topic= only narrows replay input")


def apply_bool_selector(token: str, selectors: Selectors) -> bool:
    """Apply a single-token framework flag when `token` is one.

    Called by: `peel_context_selectors()` for flags such as `--test` and
    `--yes`, keeping the main argv scan from embedding flag table details.
    """
    selector_value = CONTEXT_SELECTOR_BOOL_FLAGS.get(token)
    if selector_value is None:
        return False
    key, value = selector_value
    selectors[key] = value
    return True


def context_selector_assignment(token: str) -> tuple[str | None, str | None]:
    """Return a framework replay selector assignment, if the token is one."""
    key, separator, value = token.partition("=")
    if not separator:
        return None, None
    selector = CONTEXT_SELECTOR_KEYS.get(key)
    if selector is None:
        return None, None
    if not value:
        raise ValueError(f"--from {key}= requires a value")
    return selector, value
