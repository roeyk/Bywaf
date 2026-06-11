"""Prompt secret-span overlay styling.

Used by: `completion.prompt.BywafPromptLexer` to let focused secret-input spans override
normal value/string syntax highlighting.
"""

from __future__ import annotations


def overlay_secret_fragments(base_fragments: list[tuple[str, str]], secret_fragments: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Let secret-span styling override value/string styling."""
    secret_style_by_index: dict[int, str] = {}
    position = 0
    for style, text in secret_fragments:
        if style:
            for offset in range(len(text)):
                secret_style_by_index[position + offset] = style
        position += len(text)
    if not secret_style_by_index:
        return base_fragments
    return apply_secret_styles(base_fragments, secret_style_by_index)


def apply_secret_styles(base_fragments: list[tuple[str, str]], secret_style_by_index: dict[int, str]) -> list[tuple[str, str]]:
    """Merge base prompt fragments with per-character secret styles."""
    merged: list[tuple[str, str]] = []
    position = 0
    for style, text in base_fragments:
        for char in text:
            final_style = secret_style_by_index.get(position, style)
            if merged and merged[-1][0] == final_style:
                merged[-1] = (final_style, f"{merged[-1][1]}{char}")
            else:
                merged.append((final_style, char))
            position += 1
    return merged
