"""Runtime note commandlet.

Provides the bundled `runtime.note` plugin implementation and CommandSpec
metadata. Operators use this commandlet to attach and review notes for jobs,
pipelines, and pipeline steps.

Used by:
- PluginRegistry discovery: loads this package as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
"""


from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)

from .completion import complete_note_args
from .events import add_note, format_note_event, select_note_events
from .selectors import parse_note_args


@commandlet(
    name="note",
    description="Show or save notes attached to jobs, pipelines, and pipeline steps.",
    usage="note [add] <step=id|pipeline=id|job=id> [text=note|file=path]",
    examples=(
        "note step=1",
        "note pipeline=1",
        "note job=12 file=notes.txt",
        "note add step=1 text=follow-up note",
    ),
)
@argument(
    "selector",
    "add, step=, pipeline=, or job= selector",
    completion=CompletionSpec("choice", ("add", "step=", "pipeline=", "job=")),
)
@argument("value", "optional text= note or file= path", required=False, completion="path")
class Note(CommandletBase):
    """Display timestamped notes recorded by framework-level `note=` selectors."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify note creation separately from note display/export."""
        return ("write",) if args and args[0] == "add" else ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Show matching notes or save them to a file."""
        del input_events
        mode, selectors = parse_note_args(args)
        if mode == "add":
            add_note(context, selectors)
            return ()
        # Display and export share the same selector pipeline; only the final
        # sink differs between console output and a filesystem write.
        events = select_note_events(context, selectors)
        lines = [format_note_event(event) for event in events]
        if "file" in selectors:
            path = Path(selectors["file"]).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            context.audit_capability("filesystem.write")
            path.write_text("\n".join(lines) + ("\n" if lines else ""))
            context.output(f"saved {len(lines)} notes to {path}")
        else:
            for line in lines:
                context.output(line)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete note selectors and file paths."""
        return complete_note_args(context, args, prefix)


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Note()
