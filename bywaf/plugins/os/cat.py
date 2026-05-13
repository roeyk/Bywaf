"""Local file printing commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, Commandlet, CompletionSpec
from bywaf.plugins.os.files import print_file


class Cat:
    """Commandlet wrapper around local text-file output."""

    spec = CommandSpec(
        name="cat",
        description="Print a local text file.",
        usage="cat <path>",
        examples=("cat README.md",),
        arguments=(
            ArgumentSpec("path", "file to print", completion=CompletionSpec("file")),
        ),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `cat <path>` and write the file contents to stdout."""

        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path")
        parsed = parser.parse_args(args)
        print_file(Path(parsed.path))
        return ()


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Cat()
