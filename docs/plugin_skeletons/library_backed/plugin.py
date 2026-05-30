"""Library-backed Bywaf plugin skeleton.

Use this when a commandlet imports a third-party Python package in-process.
Declare `library_backed = true` in the manifest. Keep dependency failures
clear and user-facing.
"""

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet


# LLM Guardrail: @commandlet decorates the CommandletBase class, not plugin().
# Do not move @commandlet or @argument onto the plugin() factory function.
@commandlet(
    name="example_library_check",
    description="Example library-backed commandlet.",
    usage="example_library_check <target>",
    emits=("example.library.result",),
    capabilities=("framework.console.output", "network.connect"),
)
@argument("target", "Target value to inspect", required=True)
class ExampleLibraryCheck(CommandletBase):
    """Place third-party library usage in run() or helper modules."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        del input_events
        parser = self.parser()
        parser.add_argument("target")
        parsed = parser.parse_args(args)

        # Place third-party library import/use here or in a helper module.
        # If the import can fail, raise a clear ValueError explaining which
        # package the user needs to install.
        context.output(f"checked {parsed.target}")
        yield {"target": parsed.target, "status": "checked"}


def plugin() -> Commandlet:
    return ExampleLibraryCheck()
