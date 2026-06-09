"""Runtime results commandlet.

Provides an operator-facing view for "what did this scan find?" over the
event ledger.  Specialized result topics, such as `port.open`, are rendered
with domain-specific tables; other topics fall back to concise inserted-topic
and representative-event summaries.

Used by:
- REPL operators: inspect the latest or selected scan results.
- runtime pipeline detail: point users from pipeline structure to results."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.network.portscanner.ports import PORT_SORT_KEYS
from bywaf.plugins.runtime.results.follow import follow_results
from bywaf.plugins.runtime.results.render import no_results_message, render_results
from bywaf.plugins.runtime.results.scope import select_result_scope
from bywaf.plugins.runtime.results.selectors import parse_results_selectors
from bywaf.runtime_display import (
    runtime_sort_completion_candidates,
)


@commandlet(
    name="results",
    description="Show what the latest or selected scan found.",
    usage="results [--follow] [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true] [sort=<key>]",
    examples=(
        "results",
        "results --follow",
        "results sort=port",
        "results pipeline=1",
        "results step=2",
        "results job=latest",
    ),
)
class Results(CommandletBase):
    """Show scan results without exposing the raw event ledger by default."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Select a result scope and render useful inserted records."""
        del input_events
        parser = self.parser()
        parser.add_argument("--follow", action="store_true")
        parser.add_argument("--page", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        selectors = parse_results_selectors(tokens)
        context.require_foreground("result views")
        if parsed.follow:
            follow_results(context, selectors)
            return ()
        scope = select_result_scope(context, selectors)
        if not scope.events:
            context.output(no_results_message(context))
            return ()
        output = render_results(context, scope)
        if parsed.page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete result scope selectors."""
        del context
        if args and args[-1].startswith("sort="):
            return runtime_sort_completion_candidates(args[-1], PORT_SORT_KEYS)
        candidates = ["--follow", "--page", "all=true", "interval=", "job=", "job=latest", "once=", "pipeline=", "step=", "sort="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


@commandlet(
    name="result",
    description="Alias for results.",
    usage="result [--follow] [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true] [sort=<key>]",
    examples=("result", "result --follow", "result sort=port", "result pipeline=1", "result step=2"),
)
class ResultAlias(Results):
    """Backwards-free synonym for the singular spelling operators try first."""


def plugins() -> tuple[Commandlet, ...]:
    """Return plural and singular result commandlets."""
    return (Results(), ResultAlias())
