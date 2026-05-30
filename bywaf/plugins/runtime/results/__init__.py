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
from collections.abc import Iterable
import time

from bywaf.event.schemas import event_schema
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.network.portscanner.ports import PORT_SORT_KEYS
from bywaf.plugins.runtime.job import require_job
from bywaf.plugins.runtime.results.render import no_results_message, render_results
from bywaf.runtime_display import (
    parse_runtime_sort,
    runtime_sort_completion_candidates,
)

RESULT_SCOPE_KEYS = {"all", "interval", "job", "once", "pipeline", "step", "sort"}

# `results` is an operator-facing product view, not a raw audit log.  These
# framework/UI topics are still visible through `event`, but they should never
# decide what "the latest scan result" is.
NOISE_TOPIC_PREFIXES = (
    "artifact.",
    "bundle.",
    "command.run.",
    "console.",
    "db.",
    "framework.",
    "job.",
    "key.",
    "note.",
    "plugin.capability.",
    "plugin.progress.",
    "project.",
    "report.",
    "resource.",
    "runtime.",
    "shell.",
    "trigger.",
    "watchdog.",
)
NOISE_TOPICS = {"process.run", "runtime.name.assigned"}
RESULT_VIEW_COMMANDS = {
    "artifact",
    "bundle",
    "event",
    "events",
    "job",
    "pipeline",
    "port",
    "ports",
    "report",
    "result",
    "results",
    "step",
}


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
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
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
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class ResultAlias(Results):
    """Backwards-free synonym for the singular spelling operators try first."""


def parse_results_selectors(tokens: list[str]) -> Namespace:
    """Parse `results` selector tokens into a single runtime scope."""
    scope: dict[str, str] = {}
    sort_key = "host"
    interval = 1.0
    once = False
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"results uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("results selectors must be key=value")
        if key not in RESULT_SCOPE_KEYS:
            raise ValueError("results selectors must be one of: all, job, pipeline, step, sort")
        if key == "interval":
            interval = parse_results_interval(value)
        elif key == "once":
            once = parse_results_boolean(value, "once")
        elif key == "sort":
            sort_key = parse_runtime_sort(value, PORT_SORT_KEYS, "results")
        else:
            scope[key] = value
    validate_results_scope(scope)
    return Namespace(scope=scope, sort=sort_key, interval=interval, once=once)


def parse_results_interval(raw: str) -> float:
    """Parse follow polling interval seconds."""
    try:
        interval = float(raw)
    except ValueError as exc:
        raise ValueError(f"invalid results interval= value: {raw}") from exc
    if interval <= 0:
        raise ValueError("results interval= must be greater than 0")
    return interval


def parse_results_boolean(raw: str, key: str) -> bool:
    """Parse true/false selector values."""
    value = raw.casefold()
    if value in {"true", "yes", "1", "on"}:
        return True
    if value in {"false", "no", "0", "off"}:
        return False
    raise ValueError(f"results {key}= must be true or false")


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
        return Namespace(label="all results", scope={"all": "true"}, sort=selectors.sort, events=non_noise_events(events.events_matching(limit=10000)))
    if "job" in scope:
        if scope["job"] == "latest":
            return latest_result_scope(context, sort=selectors.sort)
        row = require_job(context, scope["job"])
        return Namespace(label=f"job={row['id']}", scope={"job": str(row["id"])}, sort=selectors.sort, events=non_noise_events(events.events_for_job(row["id"], limit=10000)))
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return Namespace(
            label=f"pipeline={scope['pipeline']}",
            scope={"pipeline": scope["pipeline"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(pipeline_id=pipeline_id, limit=10000)),
        )
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return Namespace(
            label=f"step={scope['step']}",
            scope={"step": scope["step"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(command_run_id=run_id, limit=10000)),
        )
    return latest_result_scope(context, sort=selectors.sort)


def latest_result_scope(context: CommandContext, *, sort: str = "host") -> Namespace:
    """Return the newest operator work scope.

    Default `results` should follow the last scan-like job the operator ran,
    even when that job is still running or found nothing.  Falling back to an
    older productive step would make the command answer a different question
    than "what did the thing I just ran find?"
    """
    events = context.event_store("results latest")
    runtime = context.runtime_store("results latest")
    for row in reversed(runtime.jobs(active_only=False)):
        if context.job_id is not None and str(row["id"]) == str(context.job_id):
            continue
        if not is_result_work_job(str(row["command_line"])):
            continue
        rows = non_noise_events(events.events_for_job(row["id"], limit=10000))
        return Namespace(label=f"latest job={row['id']}", scope={"job": str(row["id"])}, sort=sort, events=rows)
    run_aliases = runtime.run_aliases()
    for row in reversed(runtime.runs(active_only=False)):
        run_id = str(row["command_run_id"])
        rows = non_noise_events(events.events_matching(command_run_id=run_id, limit=10000))
        if rows:
            step_id = run_aliases.get(run_id, run_id)
            return Namespace(label=f"latest step={step_id}", scope={"step": step_id}, sort=sort, events=rows)
    return Namespace(label="latest results", scope={}, sort=sort, events=[])


def is_result_work_job(command_line: str) -> bool:
    """Return whether a job should own the default `results` answer."""
    command = command_line.strip().split(maxsplit=1)[0] if command_line.strip() else ""
    command = command.rsplit("/", 1)[-1]
    return command not in RESULT_VIEW_COMMANDS


def follow_results(context: CommandContext, selectors: Namespace) -> None:
    """Poll and render the selected result scope until Ctrl-C."""
    last_signature: tuple[int | None, int] | None = None
    print("following results; press Ctrl-C to stop")
    try:
        while True:
            scope = select_result_scope(context, selectors)
            signature = result_scope_signature(scope.events)
            if signature != last_signature:
                if scope.events:
                    print(render_results(context, scope), flush=True)
                else:
                    print(no_results_message(context), flush=True)
                last_signature = signature
                if selectors.once:
                    return
            elif selectors.once:
                return
            time.sleep(selectors.interval)
    except KeyboardInterrupt:
        print("stopped following results")


def result_scope_signature(events: list[Event]) -> tuple[int | None, int]:
    """Return a cheap change detector for a rendered result scope."""
    if not events:
        return (None, 0)
    return (max(event.id or 0 for event in events), len(events))


def non_noise_events(events: list[Event]) -> list[Event]:
    """Filter lifecycle/audit noise out of operator result views."""
    return [event for event in events if not is_noise_topic(event.topic)]


def is_noise_topic(topic: str) -> bool:
    """Return whether a topic is lifecycle/audit noise for result display."""
    if event_schema(topic) is not None:
        return False
    return topic in NOISE_TOPICS or topic.startswith(NOISE_TOPIC_PREFIXES)


def plugins() -> tuple[Commandlet, ...]:
    """Return plural and singular result commandlets."""
    return (Results(), ResultAlias())
