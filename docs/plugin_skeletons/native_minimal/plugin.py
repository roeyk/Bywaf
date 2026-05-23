"""Minimal native Bywaf plugin skeleton.

Use this when one small commandlet is enough. For vulnerability/CVE logic,
prefer the multi-file native_vulnerability skeleton instead.
"""

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet


# LLM Guardrail: @commandlet decorates the CommandletBase class, not plugin().
# Do not move @commandlet or @argument onto the plugin() factory function.
@commandlet(
    name="example_minimal",
    description="Minimal example commandlet.",
    usage="example_minimal <target>",
    examples=("example_minimal example.test",),
    emits=("example.observed",),
    capabilities=("framework.console.output",),
)
@argument("target", "Target value to process", required=True)
class ExampleMinimal(CommandletBase):
    """Keep small plugins simple; put real work in run()."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        # This commandlet is standalone, so it does not consume pipeline input.
        del input_events

        parser = self.parser()
        parser.add_argument("target")
        parsed = parser.parse_args(args)

        # Place tiny native plugin logic here.
        context.output(f"observed {parsed.target}")
        yield {"target": parsed.target, "status": "observed"}


def plugin() -> Commandlet:
    """Factory used by Bywaf plugin loading."""
    return ExampleMinimal()
