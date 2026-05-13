"""Local filesystem listing commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, CommandSpec, Commandlet, CompletionSpec
from bywaf.plugins.os.files import list_path


class Ls:
    """Commandlet wrapper around a local filesystem directory listing."""

    spec = CommandSpec(
        name="ls",
        description="List files in a local directory.",
        usage="ls [path]",
        examples=("ls", "ls bywaf/plugins"),
        arguments=(
            ArgumentSpec(
                "path",
                "directory or file to list",
                required=False,
                completion=CompletionSpec("path"),
            ),
        ),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `ls [path]` and print the target directory or file name."""

        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path", nargs="?", default=".")
        parsed = parser.parse_args(args)
        for line in list_path(Path(parsed.path)):
            context.output(line)
        return ()


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Ls()
