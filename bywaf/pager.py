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
    """Display a file through `less -R` when interactive, otherwise print it."""
    pager = shutil.which("less")
    if pager and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            subprocess.run([pager, "-R", str(path)], check=False)
        except KeyboardInterrupt:
            pass
        return
    print(path.read_text(errors="replace"), end="", flush=True)


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
