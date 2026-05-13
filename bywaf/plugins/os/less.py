"""Interactive local file pager commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path
import shutil
import subprocess
import sys

from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, Commandlet, CompletionSpec
from bywaf.plugins.os.files import read_text_file


class Less:
    """Commandlet wrapper around the system pager."""

    spec = CommandSpec(
        name="less",
        description="View a local text file in the system pager.",
        usage="less <path>",
        examples=("less README.md",),
        arguments=(
            ArgumentSpec("path", "file to view", completion=CompletionSpec("file")),
        ),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `less <path>` and open the file in a pager when possible."""

        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path")
        parsed = parser.parse_args(args)
        page_file(Path(parsed.path), context)
        return ()


def page_file(path: Path, context: CommandContext | None = None) -> None:
    """Use `less` interactively, falling back to plain output when needed."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_dir():
        raise ValueError(f"{path} is a directory")
    pager = shutil.which("less")
    if pager and sys.stdin.isatty() and sys.stdout.isatty():
        subprocess.run([pager, str(path)], check=False)
        return
    text = read_text_file(path)
    if context is None:
        print(text, end="")
    else:
        context.output(text, end="")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Less()
