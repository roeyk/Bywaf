"""Public selector parsing helpers for commandlets.

Used by: bundled plugins with `key=value` selector syntax, and external
plugins through `from bywaf.plugin import parse_kvs`.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence


def parse_kvs(
    tokens: Sequence[str],
    *,
    allowed_keys: Collection[str] | None = None,
    command: str = "command",
    text_keys: Collection[str] = (),
) -> dict[str, str]:
    """Parse `key=value` tokens into a selector dictionary.

    `text_keys` identifies keys whose value consumes the rest of the token
    sequence. This supports commandlets such as `note add ... text=some words`
    without each plugin reimplementing final free-text parsing.
    """
    selectors: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        key, value = parse_kv(tokens[index], command=command)
        if allowed_keys is not None and key not in allowed_keys:
            raise ValueError(f"unknown {command} selector: {key}")
        if key in text_keys:
            value = " ".join([value, *tokens[index + 1:]]).strip()
            index = len(tokens)
        else:
            index += 1
        if not value:
            raise ValueError(f"{command} selector {key}= requires a value")
        selectors[key] = value
    return selectors


def parse_kv(token: str, *, command: str = "command") -> tuple[str, str]:
    """Parse one non-empty `key=value` selector token."""
    if "=" not in token:
        raise ValueError(f"invalid {command} selector: {token}")
    key, value = token.split("=", 1)
    if not key:
        raise ValueError(f"invalid {command} selector: {token}")
    return key, value


def require_one_selector(selectors: dict[str, str], keys: Collection[str], *, command: str) -> str:
    """Validate that exactly one selector key from `keys` is present.

    Returns the present key so commandlets can branch without recalculating the
    scope list.
    """
    present = [key for key in keys if key in selectors]
    if len(present) != 1:
        labels = ", ".join(f"{key}=" for key in keys)
        raise ValueError(f"{command} requires exactly one {labels} selector")
    return present[0]
