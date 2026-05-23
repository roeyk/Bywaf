"""Process-wrapped Bywaf plugin skeleton.

Use this when a commandlet invokes an external program through
context.process.run() or context.process.stream().
"""

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, argument, commandlet

from .parser import parse_tool_output


# LLM Guardrail: @commandlet decorates the CommandletBase class, not plugin().
# Do not move @commandlet or @argument onto the plugin() factory function.
@commandlet(
    name="example_wrapped_tool",
    description="Example process-wrapped commandlet.",
    usage="example_wrapped_tool <target>",
    emits=("example.tool.result",),
    capabilities=("framework.process.run", "process.run"),
)
@argument("target", "Target value passed to the external tool", required=True)
class ExampleWrappedTool(CommandletBase):
    """Invoke an external tool through the mediated process API."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        del input_events
        parser = self.parser()
        parser.add_argument("target")
        parsed = parser.parse_args(args)

        # Place command construction here. Do not use subprocess directly.
        completed = context.process.run(["example-tool", "--json", parsed.target])
        for row in parse_tool_output(completed.stdout):
            yield {"target": parsed.target, **row}


def plugin() -> Commandlet:
    return ExampleWrappedTool()
