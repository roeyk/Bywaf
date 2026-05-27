"""Terminal pager helpers.

Provides one implementation for sending generated text or existing files to an
interactive pager while falling back to plain stdout for redirected output.

Used by:
- framework request handling: page commandlet-generated files.
- REPL display helpers: page built-in generated listings."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def page_file(path: Path) -> None:
    """Display a file inline when it fits, otherwise through `less -R`."""
    text = path.read_text(errors="replace")
    if not should_use_pager(text):
        print(text, end="", flush=True)
        return
    pager = shutil.which("less")
    if pager and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            subprocess.run([pager, "-R", str(path)], check=False)
        except KeyboardInterrupt:
            pass
        return
    print(text, end="", flush=True)


def should_use_pager(text: str) -> bool:
    """Return whether text exceeds the current interactive terminal size."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    size = shutil.get_terminal_size(fallback=(80, 24))
    lines = text.splitlines() or [""]
    # Leave one row for the shell prompt/status area. Wide rows need paging even
    # when the line count is small, because horizontal overflow is hard to scan.
    return len(lines) > max(size.lines - 1, 1) or any(len(line) > size.columns for line in lines)


def page_text(text: str, *, suffix: str = ".txt") -> None:
    """Write generated text to a temporary file and page it."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as handle:
        handle.write(text)
        if text and not text.endswith("\n"):
            handle.write("\n")
        path = Path(handle.name)
    try:
        page_file(path)
    finally:
        path.unlink(missing_ok=True)
