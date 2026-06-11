"""Prompt-toolkit style translation helpers.

Used by: `prompt.value_render` and `completion.prompt` to translate Bywaf display/style
variables into prompt-toolkit fragment style strings.
"""

from __future__ import annotations

DISPLAY_STYLE_PREFIX = "display/style."
DISPLAY_VALUE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}value"
DISPLAY_STRING_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}string"
DISPLAY_VARIABLE_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}variable"

# prompt_fragment_style() translates Bywaf display/style variables into
# prompt-toolkit fragment style names. This table covers named ANSI colors;
# dynamic rgb:/colorNN forms are handled by the parser below.
PROMPT_TOOLKIT_COLOR_NAMES = {
    "black": "ansiblack",
    "red": "ansired",
    "green": "ansigreen",
    "yellow": "ansiyellow",
    "blue": "ansiblue",
    "magenta": "ansimagenta",
    "cyan": "ansicyan",
    "white": "ansiwhite",
    "bright-black": "ansibrightblack",
    "bright-red": "ansibrightred",
    "bright-green": "ansibrightgreen",
    "bright-yellow": "ansibrightyellow",
    "bright-blue": "ansibrightblue",
    "bright-magenta": "ansibrightmagenta",
    "bright-cyan": "ansibrightcyan",
    "bright-white": "ansibrightwhite",
}

# prompt_fragment_style() also allows a small set of prompt-toolkit text
# attributes to be mixed with the color name in one style string.
PROMPT_TOOLKIT_ATTR_NAMES = {
    "bold",
    "italic",
    "underline",
    "reverse",
}


def prompt_fragment_style(style: str) -> str:
    """Translate Bywaf display-style tokens into prompt-toolkit fragments."""
    parts: list[str] = []
    for token in style.split():
        normalized = token.strip().casefold().replace("_", "-")
        if not normalized:
            continue
        if normalized in PROMPT_TOOLKIT_ATTR_NAMES:
            parts.append(normalized)
        elif normalized in {"dim", "blink", "strikethrough"}:
            continue
        elif normalized in PROMPT_TOOLKIT_COLOR_NAMES:
            parts.append(PROMPT_TOOLKIT_COLOR_NAMES[normalized])
        elif normalized.startswith("#") and len(normalized) in {4, 7}:
            parts.append(normalized)
        elif normalized.startswith("rgb:"):
            hex_color = rgb_style_to_hex(normalized)
            if hex_color:
                parts.append(hex_color)
    return " ".join(parts)


def rgb_style_to_hex(token: str) -> str | None:
    """Convert `rgb:R,G,B` into a prompt-toolkit hex color."""
    try:
        values = [int(part.strip()) for part in token.removeprefix("rgb:").split(",")]
    except ValueError:
        return None
    if len(values) != 3 or any(value < 0 or value > 255 for value in values):
        return None
    return "#" + "".join(f"{value:02x}" for value in values)
