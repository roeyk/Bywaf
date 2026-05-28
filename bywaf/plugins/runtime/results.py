"""Runtime results commandlet.

Provides an operator-facing view for "what did this scan find?" over the
event ledger.  Specialized result topics, such as `port.open`, are rendered
with domain-specific tables; other topics fall back to concise inserted-topic
and representative-event summaries.

Used by:
- REPL operators: inspect the latest or selected scan results.
- runtime pipeline detail: point users from pipeline structure to results."""

from __future__ import annotations

from argparse import Namespace
from collections import Counter
from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.network.portscanner_ports import render_ports
from bywaf.plugins.runtime.job import require_job
from bywaf.repl.display.events import format_event
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width

RESULT_SCOPE_KEYS = {"all", "job", "pipeline", "step"}
NOISE_TOPIC_PREFIXES = ("command.run.", "plugin.capability.", "plugin.progress.")
NOISE_TOPICS = {"framework.console.output.requested", "console.output", "runtime.name.assigned"}


@commandlet(
    name="results",
    description="Show what the latest or selected scan found.",
    usage="results [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true]",
    examples=(
        "results",
        "results pipeline=1",
        "results step=2",
        "results job=latest",
    ),
    capabilities=("framework.console.output", "framework.file.page"),
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
        parser.add_argument("--page", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        selectors = parse_results_selectors(tokens)
        context.require_foreground("result views")
        scope = select_result_scope(context, selectors)
        if not scope.events:
            context.output("no results")
            return ()
        output = render_results(context, scope)
        if parsed.page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete result scope selectors."""
        del context, args
        candidates = ["--page", "all=true", "job=", "job=latest", "pipeline=", "step="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


@commandlet(
    name="result",
    description="Alias for results.",
    usage="result [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true]",
    examples=("result", "result pipeline=1", "result step=2"),
    capabilities=("framework.console.output", "framework.file.page"),
)
class ResultAlias(Results):
    """Backwards-free synonym for the singular spelling operators try first."""


def parse_results_selectors(tokens: list[str]) -> Namespace:
    """Parse `results` selector tokens into a single runtime scope."""
    scope: dict[str, str] = {}
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"results uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("results selectors must be key=value")
        if key not in RESULT_SCOPE_KEYS:
            raise ValueError("results selectors must be one of: all, job, pipeline, step")
        scope[key] = value
    validate_results_scope(scope)
    return Namespace(scope=scope)


def validate_results_scope(scope: dict[str, str]) -> None:
    """Reject ambiguous result scopes."""
    all_value = scope.get("all", "false")
    if all_value not in {"true", "false"}:
        raise ValueError("results all= must be true or false")
    explicit_scopes = [key for key in ("job", "pipeline", "step") if key in scope]
    if all_value == "true" and explicit_scopes:
        raise ValueError("results all=true cannot be combined with job=, pipeline=, or step=")
    if len(explicit_scopes) > 1:
        raise ValueError("results accepts only one runtime scope: job=, pipeline=, or step=")


def select_result_scope(context: CommandContext, selectors: Namespace) -> Namespace:
    """Return events for an explicit scope or the latest productive step."""
    scope = selectors.scope
    events = context.event_store("results")
    runtime = context.runtime_store("results")
    if scope.get("all") == "true":
        return Namespace(label="all results", scope={}, events=non_noise_events(events.events_matching(limit=10000)))
    if "job" in scope:
        if scope["job"] == "latest":
            return latest_result_scope(context)
        row = require_job(context, scope["job"])
        return Namespace(label=f"job={row['id']}", scope={"job": str(row["id"])}, events=non_noise_events(events.events_for_job(row["id"], limit=10000)))
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return Namespace(
            label=f"pipeline={scope['pipeline']}",
            scope={"pipeline": scope["pipeline"]},
            events=non_noise_events(events.events_matching(pipeline_id=pipeline_id, limit=10000)),
        )
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return Namespace(
            label=f"step={scope['step']}",
            scope={"step": scope["step"]},
            events=non_noise_events(events.events_matching(command_run_id=run_id, limit=10000)),
        )
    return latest_result_scope(context)


def latest_result_scope(context: CommandContext) -> Namespace:
    """Return the newest step with non-lifecycle inserted events."""
    events = context.event_store("results latest")
    runtime = context.runtime_store("results latest")
    run_aliases = runtime.run_aliases()
    for row in reversed(runtime.runs(active_only=False)):
        run_id = str(row["command_run_id"])
        rows = non_noise_events(events.events_matching(command_run_id=run_id, limit=10000))
        if rows:
            step_id = run_aliases.get(run_id, run_id)
            return Namespace(label=f"latest step={step_id}", scope={"step": step_id}, events=rows)
    return Namespace(label="latest results", scope={}, events=[])


def render_results(context: CommandContext, scope: Namespace) -> str:
    """Render result-like events with specialized views where possible."""
    sections = [f"Results: {scope.label}"]
    port_events = [event for event in scope.events if event.topic == "port.open"]
    if port_events:
        sections.append(render_ports(context, port_events, Namespace(scope=scope.scope, filters={}, sort="host")))
    other_events = [event for event in scope.events if event.topic != "port.open"]
    if other_events:
        sections.append(render_event_topic_summary(context, other_events))
        sections.append(render_representative_events(context, other_events))
    return "\n\n".join(section for section in sections if section)


def render_event_topic_summary(context: CommandContext, events: list[Event]) -> str:
    """Render inserted event topic counts."""
    counts = Counter(event.topic for event in events)
    rows = [(topic, count) for topic, count in sorted(counts.items())]
    return "Inserted events\n" + render_table(
        ("TOPIC", "COUNT"),
        rows,
        cell_subjects=("event.topic", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_representative_events(context: CommandContext, events: list[Event], *, limit: int = 10) -> str:
    """Render a small sample of raw records for unfamiliar result topics."""
    del context
    return "Representative events\n" + "\n".join(format_event(event) for event in events[:limit])


def non_noise_events(events: list[Event]) -> list[Event]:
    """Filter lifecycle/audit noise out of operator result views."""
    return [event for event in events if not is_noise_topic(event.topic)]


def is_noise_topic(topic: str) -> bool:
    """Return whether a topic is lifecycle/audit noise for result display."""
    return topic in NOISE_TOPICS or topic.startswith(NOISE_TOPIC_PREFIXES)


def plugins() -> tuple[Commandlet, ...]:
    """Return plural and singular result commandlets."""
    return (Results(), ResultAlias())
