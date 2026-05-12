"""Local file printing commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import CommandContext, CommandSpec, Commandlet
from bywaf.plugins.os.files import print_file


class Cat:
    spec = CommandSpec(
        name="cat",
        description="Print a local text file.",
        usage="cat <path>",
        examples=("cat README.md",),
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
        print_file(Path(parsed.path))
        return ()


def plugin() -> Commandlet:
    return Cat()
