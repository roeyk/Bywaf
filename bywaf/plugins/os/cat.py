"""File display commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Prints file content through framework console output events.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet
from bywaf.plugins.os.files import read_text_file


@commandlet(
    name="cat",
    description="Print a local text file.",
    usage="cat <path>",
    examples=("cat README.md",),
    capabilities=("filesystem.read", "framework.console.output"),
)
@argument("path", "file to print", completion="file")
class Cat(CommandletBase):
    """Commandlet wrapper around local text-file output."""

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
        # The filesystem read is explicit even though the helper performs the
        # actual IO; this keeps capability audit close to command intent.
        context.audit_capability("filesystem.read")
        context.output(read_text_file(Path(parsed.path)), end="")
        return ()


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Cat()
