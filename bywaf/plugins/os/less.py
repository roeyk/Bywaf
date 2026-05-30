"""Paged file display commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Shows local file content through the configured pager when available.

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
    name="less",
    description="View a local text file through the framework pager.",
    usage="less <path>",
    examples=("less README.md",),
    capabilities=("filesystem.read", "framework.file.page"),
)
@argument("path", "file to view", completion="file")
class Less(CommandletBase):
    """Commandlet wrapper around framework-owned file paging."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse `less <path>` and open the file in a pager when possible."""

        parser = self.parser()
        parser.add_argument("path")
        parsed = parser.parse_args(args)
        context.audit_capability("filesystem.read")
        page_file(Path(parsed.path), context)
        return ()


def page_file(path: Path, context: CommandContext | None = None) -> None:
    """Request framework-owned paging, falling back to plain output without DB."""

    if not path.exists():
        raise ValueError(f"{path} does not exist")
    if path.is_dir():
        raise ValueError(f"{path} is a directory")
    if context is not None:
        # Context owns paging so tests, CLI, and future UIs can choose their
        # own display backend without changing this plugin.
        context.page_file(path)
        return
    print(read_text_file(path), end="")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""

    return Less()
