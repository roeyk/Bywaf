"""Service commandlet plus provider-owned trigger skeleton."""

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet

from .triggers import triggers


# LLM Guardrail: @commandlet decorates the CommandletBase class, not plugin().
# Do not move @commandlet onto the plugin() factory function.
@commandlet(
    name="example_service",
    description="Example session service started by a provider-owned trigger.",
    usage="example_service [--session-service]",
    emits=("example.service.observed",),
    capabilities=("db.read:*", "framework.console.output"),
)
class ExampleService(CommandletBase):
    """Place service loop logic here.

    Keep loops cooperative: check context.cancelled(), sleep reasonably, and
    emit progress/observations instead of busy-waiting.
    """

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        del input_events
        parser = self.parser()
        parser.add_argument("--session-service", action="store_true")
        parsed = parser.parse_args(args)

        context.output("example service started")
        if parsed.session_service:
            # Place bounded/cooperative service loop here.
            yield {"mode": "session-service", "status": "started"}
        else:
            yield {"mode": "foreground", "status": "ran"}


def plugin() -> Commandlet:
    return ExampleService()
