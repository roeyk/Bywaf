"""Finding severity normalization and operational classes.

Provides helpers that map normalized finding severities to broad operator
urgency classes without requiring plugins to emit another payload field.

Used by:
- report rendering: style and summarize findings by operational urgency.
- docs/tests: keep severity-class behavior stable for plugin authors.
"""

from __future__ import annotations


SEVERITY_CLASSES = {
    "info": "informational",
    "informational": "informational",
    "low": "advisory",
    "medium": "review",
    "moderate": "review",
    "high": "urgent",
    "critical": "emergency",
}

SEVERITY_CLASS_ORDER = ("informational", "advisory", "review", "urgent", "emergency", "unknown")


def severity_class(severity: object) -> str:
    """Return the broad operational class for a normalized severity value."""
    normalized = str(severity or "").strip().casefold()
    return SEVERITY_CLASSES.get(normalized, "unknown")
