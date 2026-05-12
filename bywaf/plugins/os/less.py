"""Interactive local file pager commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path
import shutil
import subprocess
import sys

from bywaf.events import Event
from bywaf.plugin import CommandContext, CommandSpec, Commandlet
from bywaf.plugins.os.files import print_file


class Less:
    spec = CommandSpec(
        name="less",
        description="View a local text file in the system pager.",
        usage="less <path>",
        examples=("less README.md",),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path")
        parsed = parser.parse_args(args)
        page_file(Path(parsed.path))
        return ()


def page_file(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_dir():
        raise ValueError(f"{path} is a directory")
    pager = shutil.which("less")
    if pager and sys.stdin.isatty() and sys.stdout.isatty():
        subprocess.run([pager, str(path)], check=False)
        return
    print_file(path)


def plugin() -> Commandlet:
    return Less()
