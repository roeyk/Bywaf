"""Structured diagnostics for nmap-backed plugins.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from bywaf.plugin import CommandContext

from .nmap_backend import NmapScanError, NmapUnavailableError

NMAP_FAILURES = (NmapUnavailableError, NmapScanError)


def publish_nmap_error(context: CommandContext, exc: NmapUnavailableError | NmapScanError, *, phase: str) -> None:
    """Publish a normalized nmap tool-error event for wrapper failures."""
    context.events.publish(
        "tool.error",
        {
            "tool": "nmap",
            "severity": "error",
            "message": str(exc),
            "phase": phase,
            "exception": type(exc).__name__,
        },
    )
