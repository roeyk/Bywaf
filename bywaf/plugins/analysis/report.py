"""Operator-facing report commandlet.

Provides the first reporting inbox over normalized finding events. It renders
grouped findings for recent, step-scoped, job-scoped, or pipeline-scoped work
without requiring operators to inspect raw event payloads.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    commandlet,
    option,
)
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.analysis.finding_report import REPORT_FINDING_TOPICS

from .report_events import select_report_scope_events
from .report_render import render_finding_report
from .report_review import REVIEW_DECISIONS, review_report_groups

REPORT_ACTIONS = ("accept", "defer", "reject", "detail")
REPORT_REVIEW_ACTIONS = tuple(REVIEW_DECISIONS)
REPORT_OPTION_KEYS = {"job", "pipeline", "step", "limit", "note", "page", "status"}
REPORT_STATUS_CHOICES = ("all", "accepted", "deferred", "rejected", "unreviewed")


@commandlet(
    name="report",
    description="Show grouped finding reports for recent, step, job, or pipeline scopes.",
    usage=(
        "report [<index-range>|detail <index-range>|accept|defer|reject <index-range|all>] "
        "[pipeline=<ids>] [job=<ids>] [step=<ids>] [status=<filter>]"
    ),
    examples=(
        "report",
        "report 1",
        "report detail 1-3",
        "report accept 1-3,7",
        "report defer 4 note=needs manual validation",
        "report pipeline=1",
        "report page=false",
        "report pipeline=1,2,3",
        "report job=7",
        "report step=12",
    ),
    consumes=REPORT_FINDING_TOPICS,
    emits=("report.rendered",),
    capabilities=(
        "db.read:finding.new",
        "db.read:finding.candidate",
        "db.read:finding.merge_candidate",
        "db.read:finding.reviewed",
        "db.read:artifact.attached",
        "db.write:report.rendered",
        "db.write:finding.reviewed",
        "finding.review",
        "framework.console.output",
        "framework.file.page",
    ),
    database_actions=("view", "write"),
)
@option("job", "job id or comma-separated job ids", completion="job")
@option("pipeline", "pipeline id or comma-separated pipeline ids", completion="pipeline")
@option("step", "step id or comma-separated step ids", completion="step")
@option("limit", "maximum events to inspect", "1000")
@option("page", "page rendered report output", "true", ("true", "false"))
@option("status", "finding review status filter", "unreviewed", REPORT_STATUS_CHOICES)
class Report(CommandletBase):
    """Render grouped finding inboxes and scoped finding reports."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify report moderation separately from read-only report views."""
        normalized = normalize_report_args(args)
        action = next((arg for arg in normalized if not arg.startswith("-")), "")
        return ("write",) if action in REPORT_REVIEW_ACTIONS else ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and render one report view."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("action", nargs="?")
        parser.add_argument("selection", nargs="?")
        parser.add_argument("--job", default="", help="job id or comma-separated job ids")
        parser.add_argument(
            "--pipeline",
            default="",
            help="pipeline id or comma-separated pipeline ids",
        )
        parser.add_argument("--step", default="", help="step id or comma-separated step ids")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--note", default="")
        parser.add_argument("--page", choices=("true", "false"), default="false")
        parser.add_argument("--status", choices=REPORT_STATUS_CHOICES, default="unreviewed")
        parsed = parser.parse_args(normalize_report_args(args))
        normalize_report_action(parsed)

        input_findings = [event for event in input_events if event.topic in REPORT_FINDING_TOPICS]
        events = input_findings or select_report_scope_events(context, parsed)
        if parsed.action in REPORT_REVIEW_ACTIONS:
            review_report_groups(context, parsed, events)
            return ()
        render_finding_report(context, events, parsed)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete report selectors."""
        del context, args
        candidates = (
            *REPORT_ACTIONS,
            "all",
            "detail",
            "pipeline=",
            "job=",
            "step=",
            "limit=",
            "note=",
            "page=",
            "page=false",
            "page=true",
            "status=",
            "status=accepted",
            "status=all",
            "status=deferred",
            "status=rejected",
            "status=unreviewed",
        )
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def normalize_report_args(args: list[str]) -> list[str]:
    """Normalize report key=value selectors, letting final note= consume trailing text."""
    normalized: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("note="):
            note = " ".join([token.split("=", 1)[1], *args[index + 1:]]).strip()
            if not note:
                raise ValueError("report note= requires a value")
            normalized.extend(["--note", note])
            break
        normalized.append(token)
        index += 1
    return key_value_to_long_options(normalized, REPORT_OPTION_KEYS)


def normalize_report_action(parsed) -> None:
    """Normalize shorthand detail selections after argparse parsing."""
    if parsed.action is None:
        return
    if parsed.action in REPORT_ACTIONS:
        return
    # `report 1` is the common drill-down form. Treat the first positional as a
    # detail selection rather than forcing users to type `report detail 1`.
    parsed.selection = parsed.action if parsed.selection is None else f"{parsed.action},{parsed.selection}"
    parsed.action = "detail"



def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Report()
