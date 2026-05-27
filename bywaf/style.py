"""ANSI style parsing for terminal-facing renderers.

Provides shared color/style helpers for REPL display, report rendering, and
other console output paths that need user-configurable styles.

Used by:
- REPL display helpers: colorize variables, events, and syntax previews.
- report commandlet: apply theme styles to report headings and tables.
"""

from __future__ import annotations


ANSI_COLORS = {
    "black": "30",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "bold-green": "1;32",
    "bold-yellow": "1;33",
    "bright-black": "90",
    "bright-red": "91",
    "bright-green": "1;32",
    "bright-yellow": "1;33",
    "bright-blue": "94",
    "bright-magenta": "95",
    "bright-cyan": "96",
    "bright-white": "97",
}

ANSI_STYLE_TOKENS = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "blink": "5",
    "reverse": "7",
    "strikethrough": "9",
}


def ansi_color(text: str, style: str) -> str:
    """Wrap text in ANSI SGR escapes when the requested style is known."""
    code = ansi_style_code(style)
    if code is None:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def ansi_style_code(style: str) -> str | None:
    """Return one combined ANSI SGR sequence for color plus attributes."""
    codes: list[str] = []
    for token in style.split():
        normalized = token.strip().casefold().replace("_", "-")
        if not normalized:
            continue
        if normalized in ANSI_STYLE_TOKENS:
            codes.append(ANSI_STYLE_TOKENS[normalized])
            continue
        color_code = ansi_color_code(normalized)
        if color_code is not None:
            codes.append(color_code)
    return ";".join(codes) if codes else None


def ansi_color_code(color: str) -> str | None:
    """Return an SGR color code for a named, 256-color, or truecolor setting."""
    normalized = color.strip().casefold().replace("_", "-")
    if not normalized:
        return None
    if normalized in ANSI_COLORS:
        return ANSI_COLORS[normalized]
    if normalized.startswith("color"):
        number = parse_color_int(normalized.removeprefix("color"), 0, 255)
        return f"38;5;{number}" if number is not None else None
    if normalized.startswith("#"):
        rgb = parse_hex_color(normalized)
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("ansi:"):
        number = parse_color_int(normalized.removeprefix("ansi:"), 0, 255)
        return f"38;5;{number}" if number is not None else None
    if normalized.startswith("bg-ansi:"):
        number = parse_color_int(normalized.removeprefix("bg-ansi:"), 0, 255)
        return f"48;5;{number}" if number is not None else None
    if normalized.startswith("rgb:"):
        rgb = parse_rgb_color(normalized.removeprefix("rgb:"))
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("bg-rgb:"):
        rgb = parse_rgb_color(normalized.removeprefix("bg-rgb:"))
        return f"48;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    return None


def parse_hex_color(raw: str) -> tuple[int, int, int] | None:
    """Parse CSS-style `#RRGGBB` and `#RGB` colors for truecolor output."""
    value = raw.strip().removeprefix("#")
    if len(value) == 3:
        value = "".join(component * 2 for component in value)
    if len(value) != 6 or any(char not in "0123456789abcdef" for char in value):
        return None
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def parse_rgb_color(raw: str) -> tuple[int, int, int] | None:
    """Parse `R,G,B` values for truecolor terminal output."""
    parts = raw.split(",")
    if len(parts) != 3:
        return None
    red = parse_color_int(parts[0], 0, 255)
    green = parse_color_int(parts[1], 0, 255)
    blue = parse_color_int(parts[2], 0, 255)
    if red is None or green is None or blue is None:
        return None
    return red, green, blue


def parse_color_int(raw: str, minimum: int, maximum: int) -> int | None:
    """Parse one bounded color integer."""
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    if minimum <= value <= maximum:
        return value
    return None


def subject_style(getter, subject: str) -> str:
    """Return the configured style for a subject, falling back to parents."""
    current = subject
    while current:
        style = getter(f"display/style.{current}", "")
        if style:
            return str(style)
        if "." not in current:
            break
        current = current.rsplit(".", 1)[0]
    return ""


def styled_subject_text(getter, subject: str, value: object) -> str:
    """Render a value using the style configured for its semantic subject."""
    text = str(value)
    style = subject_style(getter, subject)
    return ansi_color(text, style) if style else text
