"""ANSI style parsing for terminal-facing renderers.

Provides shared color/style helpers for REPL display, report rendering, and
other console output paths that need user-configurable styles.

Used by:
- REPL display helpers: colorize variables, events, and syntax previews.
- report commandlet: apply theme styles to report headings and tables.
"""

from __future__ import annotations


# ansi_color_code() accepts friendly style names in user-configurable display
# variables. These tables translate those names into SGR numbers before the
# parser handles dynamic forms such as colorNN, rgb:, and bg:.
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
# ansi_background_color_code() consumes this companion table for bg: style
# tokens, keeping foreground and background aliases deliberately separate.
ANSI_BACKGROUND_COLORS = {
    "black": "40",
    "red": "41",
    "green": "42",
    "yellow": "43",
    "blue": "44",
    "magenta": "45",
    "cyan": "46",
    "white": "47",
    "bright-black": "100",
    "bright-red": "101",
    "bright-green": "102",
    "bright-yellow": "103",
    "bright-blue": "104",
    "bright-magenta": "105",
    "bright-cyan": "106",
    "bright-white": "107",
}

# ansi_style_code() treats these tokens as text attributes that can be combined
# with color tokens in one display style string.
ANSI_STYLE_TOKENS = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "blink": "5",
    "reverse": "7",
    "strikethrough": "9",
}
STRUCTURED_STYLE_FLAGS = frozenset(ANSI_STYLE_TOKENS)


def ansi_color(text: str, style: str) -> str:
    """Wrap text in ANSI SGR escapes when the requested style is known.

    Called by: REPL display helpers, report rendering, runtime table rendering,
    and subject-styling helpers whenever user-configured styles are applied.
    """
    code = ansi_style_code(style)
    if code is None:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def ansi_style_code(style: str) -> str | None:
    """Return one combined ANSI SGR sequence for color plus attributes.

    Used by: `ansi_color()` and tests that validate the display-style language.
    """
    # Style strings are whitespace-separated tokens. Each token can contribute
    # an attribute code, a foreground color, or be ignored if it is unknown.
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
    """Return an SGR color code for a named, 256-color, or truecolor setting.

    Used by: `ansi_style_code()` for foreground tokens and by callers that need
    to validate one foreground color token directly.
    """
    normalized = color.strip().casefold().replace("_", "-")
    if not normalized:
        return None
    # Check named colors first, then progressively parse indexed and truecolor
    # foreground/background forms such as color123, bg:blue, and rgb:1,2,3.
    if normalized in ANSI_COLORS:
        return ANSI_COLORS[normalized]
    if normalized.startswith("color"):
        number = parse_color_int(normalized.removeprefix("color"), 0, 255)
        return f"38;5;{number}" if number is not None else None
    if normalized.startswith("#"):
        rgb = parse_hex_color(normalized)
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("bg:"):
        return ansi_background_color_code(normalized.removeprefix("bg:"))
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


def ansi_background_color_code(color: str) -> str | None:
    """Return an SGR background color code for named, indexed, or truecolor input.

    Used by: `ansi_color_code()` for `bg:` tokens and tests that validate
    background-color parsing independently.
    """
    normalized = color.strip().casefold().replace("_", "-")
    if not normalized:
        return None
    if normalized in ANSI_BACKGROUND_COLORS:
        return ANSI_BACKGROUND_COLORS[normalized]
    if normalized.startswith("color"):
        number = parse_color_int(normalized.removeprefix("color"), 0, 255)
        return f"48;5;{number}" if number is not None else None
    if normalized.startswith("#"):
        rgb = parse_hex_color(normalized)
        return f"48;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    if normalized.startswith("ansi:"):
        number = parse_color_int(normalized.removeprefix("ansi:"), 0, 255)
        return f"48;5;{number}" if number is not None else None
    if normalized.startswith("rgb:"):
        rgb = parse_rgb_color(normalized.removeprefix("rgb:"))
        return f"48;2;{rgb[0]};{rgb[1]};{rgb[2]}" if rgb is not None else None
    return None


def parse_hex_color(raw: str) -> tuple[int, int, int] | None:
    """Parse CSS-style `#RRGGBB` and `#RGB` colors for truecolor output.

    Used by: foreground and background ANSI color parsers.
    """
    value = raw.strip().removeprefix("#")
    if len(value) == 3:
        # CSS short hex expands each nibble: #0f8 -> #00ff88.
        value = "".join(component * 2 for component in value)
    if len(value) != 6 or any(char not in "0123456789abcdef" for char in value):
        return None
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def parse_rgb_color(raw: str) -> tuple[int, int, int] | None:
    """Parse `R,G,B` values for truecolor terminal output.

    Used by: foreground and background `rgb:` token parsing.
    """
    parts = raw.split(",")
    if len(parts) != 3:
        return None
    # Parse each channel through the same bounded helper used by ANSI-256
    # indexes so invalid or out-of-range channels reject the whole color.
    red = parse_color_int(parts[0], 0, 255)
    green = parse_color_int(parts[1], 0, 255)
    blue = parse_color_int(parts[2], 0, 255)
    if red is None or green is None or blue is None:
        return None
    return red, green, blue


def parse_color_int(raw: str, minimum: int, maximum: int) -> int | None:
    """Parse one bounded color integer.

    Used by: ANSI-256 and truecolor parsing helpers.
    """
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    if minimum <= value <= maximum:
        return value
    return None


def subject_style(getter, subject: str) -> str:
    """Return the configured style for a subject, falling back to parents.

    Called by: runtime display helpers that style semantic subjects such as
    `host.name`, `port`, and `finding.severity`.
    """
    current = subject
    while current:
        key = f"display/style.{current}"
        style = getter(key, "")
        if style:
            return str(style)
        structured = structured_subject_style(getter, key)
        if structured:
            return structured
        # Parent fallback lets a broad style such as display/style.host apply
        # to display/style.host.name unless the child is configured directly.
        if "." not in current:
            break
        current = current.rsplit(".", 1)[0]
    return ""


def structured_subject_style(getter, key: str) -> str:
    """Return a style assembled from `.foreground`, `.background`, and flags.

    Called by: `subject_style()` when a direct `display/style.<subject>` value
    is absent but structured theme variables exist.
    """
    tokens: list[str] = []
    # Structured variables are merged into the same token language accepted by
    # ansi_style_code(), keeping config storage and rendering paths unified.
    for flag in sorted(STRUCTURED_STYLE_FLAGS):
        if truthy_style_flag(getter(f"{key}.{flag}", "")):
            tokens.append(flag)
    foreground = inherited_color_value(getter(f"{key}.foreground", ""))
    if foreground:
        tokens.append(foreground)
    background = inherited_color_value(getter(f"{key}.background", ""))
    if background:
        tokens.append(f"bg:{background}")
    return " ".join(tokens)


def truthy_style_flag(value: object) -> bool:
    """Return whether a structured style flag is enabled.

    Used by: `structured_subject_style()` for `.bold`, `.underline`, and other
    structured style flag variables.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on"}


def inherited_color_value(value: object) -> str:
    """Return a color token, treating transparent-like values as inherited.

    Used by: `structured_subject_style()` so theme authors can explicitly leave
    foreground/background unset without emitting invalid color tokens.
    """
    text = str(value).strip()
    if text.casefold() in {"", "transparent", "none", "inherit"}:
        return ""
    return text


def styled_subject_text(getter, subject: str, value: object) -> str:
    """Render a value using the style configured for its semantic subject.

    Called by: runtime display paths that know the semantic subject but should
    not duplicate style lookup and ANSI wrapping logic.
    """
    text = str(value)
    style = subject_style(getter, subject)
    return ansi_color(text, style) if style else text
