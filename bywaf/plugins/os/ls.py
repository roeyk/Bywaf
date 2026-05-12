"""Local filesystem listing commandlet."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import CommandContext, CommandSpec, Commandlet
from bywaf.plugins.os.files import list_path


class Ls:
    spec = CommandSpec(
        name="ls",
        description="List files in a local directory.",
        usage="ls [path]",
        examples=("ls", "ls bywaf/plugins"),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        parser = argparse.ArgumentParser(prog=self.spec.name)
        parser.add_argument("path", nargs="?", default=".")
        parsed = parser.parse_args(args)
        list_path(Path(parsed.path))
        return ()


def plugin() -> Commandlet:
    return Ls()
