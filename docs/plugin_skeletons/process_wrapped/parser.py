"""Parser helpers for a process-wrapped plugin.

Keep stdout/stderr parsing testable without Bywaf. Prefer structured formats
from the wrapped tool, such as JSON or XML, over fragile text scraping.
"""

from __future__ import annotations


def parse_tool_output(stdout: str) -> list[dict[str, object]]:
    """Return normalized observations from external tool output."""
    # Place structured parser logic here. Avoid ad hoc regex parsing when the
    # tool can emit JSON, XML, CSV, or another stable machine-readable format.
    if not stdout.strip():
        return []
    return [{"line": line} for line in stdout.splitlines() if line.strip()]
