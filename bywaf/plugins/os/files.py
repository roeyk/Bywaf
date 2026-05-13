"""Filesystem helpers for operating-system commandlets."""

from __future__ import annotations

from pathlib import Path


def list_path(path: Path) -> None:
    """Print one directory listing or one file name."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_file():
        print(path.name)
        return
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        suffix = "/" if child.is_dir() else ""
        print(f"{child.name}{suffix}")


def print_file(path: Path) -> None:
    """Print a text file and reject directories with a clear error."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_dir():
        raise ValueError(f"{path} is a directory")
    print(path.read_text(), end="")
