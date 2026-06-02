"""Directory listing commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Lists local files and directories for REPL-oriented inspection.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet
from bywaf.plugins.os.files import list_path


@commandlet(
    name="ls",
    description="List files in a local directory.",
    usage="ls [path]",
    examples=("ls", "ls bywaf/plugins"),
)
@argument("path", "directory or file to list", required=False, completion="path")
class Ls(CommandletBase):
    """Commandlet wrapper around a local filesystem directory listing."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `ls [path]` and print the target directory or file name."""

        parser = self.parser()
        parser.add_argument("path", nargs="?", default=".")
        parsed = parser.parse_args(args)
        # Listing metadata still counts as filesystem read capability.
        context.audit_capability("filesystem.read")
        for line in list_path(Path(parsed.path)):
            context.output(line)
        return ()


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Ls()
