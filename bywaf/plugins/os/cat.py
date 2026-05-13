"""Local file printing commandlet."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.plugin import ArgumentSpec, CommandContext, Commandlet, CommandletBase, CommandSpec, CompletionSpec
from bywaf.plugins.os.files import read_text_file


class Cat(CommandletBase):
    """Commandlet wrapper around local text-file output."""

    spec = CommandSpec(
        name="cat",
        description="Print a local text file.",
        usage="cat <path>",
        examples=("cat README.md",),
        arguments=(
            ArgumentSpec("path", "file to print", completion=CompletionSpec("file")),
        ),
        capabilities=("filesystem.read", "framework.console.output"),
    )

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `cat <path>` and write the file contents to stdout."""

        parser = self.parser()
        parser.add_argument("path")
        parsed = parser.parse_args(args)
        context.audit_capability("filesystem.read")
        context.output(read_text_file(Path(parsed.path)), end="")
        return ()


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Cat()
