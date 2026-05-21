"""Shared filesystem plugin helpers.

Provides a bundled plugin implementation and CommandSpec metadata. Provides path handling and display support for local OS commandlets.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from pathlib import Path


def list_path(path: Path) -> list[str]:
    """Return one directory listing or one file name."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_file():
        return [path.name]
    return [
        f"{child.name}{'/' if child.is_dir() else ''}"
        for child in sorted(path.iterdir(), key=lambda item: item.name)
    ]


def read_text_file(path: Path) -> str:
    """Read a text file and reject directories with a clear error."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_dir():
        raise ValueError(f"{path} is a directory")
    return path.read_text()
