"""Display preference keys and fallback styles.

Provides names for user-configurable display variables plus conservative
fallback colors used when no theme or preference overrides them.

Used by:
- display submodules: resolve event, history, variable, and syntax styles.
- theme docs/tests: keep preference keys stable."""

VAR_COLOR_MODE_VAR = "display.vars.color"
VAR_NAME_COLOR_VAR = "display.vars.name-color"
VAR_VALUE_COLOR_VAR = "display.vars.value-color"
EVENT_COLOR_MODE_VAR = "display.events.color"
EVENT_KEY_COLOR_VAR = "display.events.key-color"
DISPLAY_STYLE_PREFIX = "display/style."
DISPLAY_COMMENT_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}comment"
DISPLAY_STRING_STYLE_VAR = f"{DISPLAY_STYLE_PREFIX}string"
HISTORY_COLOR_MODE_VAR = "display.history.color"
HISTORY_TIMESTAMP_COLOR_VAR = "display.history.timestamp-color"
EVENT_COMMANDLET_COLOR = "bright-yellow"
DISPLAY_EXPANSION_VAR = "display.expansion"
DISPLAY_EXPANSION_DEFAULT = "off"

# These are fallbacks only. Operators can override them through `display.*` and
# `display/style.*` variables or preference/theme files.
DEFAULT_VAR_COLOR_MODE = "auto"
DEFAULT_VAR_NAME_COLOR = "cyan"
DEFAULT_VAR_VALUE_COLOR = "green"
DEFAULT_EVENT_COLOR_MODE = "auto"
DEFAULT_EVENT_KEY_COLOR = "green"
DEFAULT_HISTORY_COLOR_MODE = "auto"
DEFAULT_HISTORY_TIMESTAMP_COLOR = "green"
EVENT_HEADING_KEY_COLOR = "yellow"
EVENT_HEADING_VALUE_COLOR = "bright-blue"
EVENT_ID_COLOR = "bright-blue"
