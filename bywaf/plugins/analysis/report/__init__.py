"""Operator-facing report commandlet.

Provides the first reporting inbox over normalized finding events. It renders
grouped findings for recent, step-scoped, job-scoped, or pipeline-scoped work
without requiring operators to inspect raw event payloads.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    commandlet,
    option,
)
from bywaf.plugin import kv_to_args

from .events import select_report_context_events, select_new_context_events, select_new_scope_events, select_report_scope_events
from .render import render_finding_report, render_network_report
from .review import REVIEW_DECISIONS, review_report_groups
from .saved import apply_saved_report_scope, save_report_scope
from .synthesis import REPORT_ANALYZE_CHOICES, report_input_findings, synthesize_report_findings

REPORT_ACTIONS = ("accept", "confirm", "defer", "reject", "unconfirm", "create", "detail", "network", "show", "update")
REPORT_REVIEW_ACTIONS = tuple(REVIEW_DECISIONS)
REPORT_SAVE_ACTIONS = ("create", "update")
REPORT_OPTION_KEYS = {"analyze", "cve", "job", "pipeline", "step", "limit", "name", "note", "page", "sort", "status"}
REPORT_STATUS_CHOICES = ("all", "accepted", "confirmed", "deferred", "open", "rejected", "unreviewed")
REPORT_SORT_CHOICES = ("finding", "host")


@commandlet(
    name="report",
    description="Show grouped finding reports for recent, step, job, or pipeline scopes.",
    usage=(
        "report [--last|--new|network|<index-range>|detail <index-range>|accept|confirm|defer|reject|unconfirm <index-range|all>] "
        "[pipeline=<ids>] [job=<ids>] [step=<ids>] [status=<filter>] [cve=<id|pattern>] [analyze=passive|off]"
    ),
    examples=(
        "report",
        "report --last",
        "report --new",
        "http_probe https://example.test/ | webfin | report",
        "report network",
        "report 1",
        "report detail 1-3",
        "report accept 1-3,7",
        "report confirm 1 note=validated manually",
        "report unconfirm 1 status=confirmed",
        "report create name=quarterly pipeline=1,2,3",
        "report show name=quarterly",
        "report update name=quarterly pipeline=1,2,3,4",
        "report defer 4 note=needs manual validation",
        "report pipeline=1",
        "report page=false",
        "report --accepted-first status=all",
        "report --candidates-first status=all",
        "report sort=host",
        "report sort=finding",
        "report analyze=off",
        "report pipeline=1,2,3",
        "report job=7",
        "report step=12",
        "report cve=CVE-2021-*",
    ),
)
@option("job", "job id or comma-separated job ids", completion="job")
@option("pipeline", "pipeline id or comma-separated pipeline ids", completion="pipeline")
@option("step", "step id or comma-separated step ids", completion="step")
@option("name", "saved report scope name")
@option("cve", "CVE selector; accepts comma-separated values and * wildcards")
@option("limit", "maximum events to inspect", "1000")
@option("analyze", "run passive report synthesis before rendering", "passive", REPORT_ANALYZE_CHOICES)
@option("page", "page rendered report output", "true", ("true", "false"))
@option("sort", "group report rows by finding or host", "finding", REPORT_SORT_CHOICES)
@option("status", "finding review status filter", "open", REPORT_STATUS_CHOICES)
class Report(CommandletBase):
    """Render grouped finding inboxes and scoped finding reports."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify report moderation separately from read-only report views."""
        normalized = normalize_report_args(args)
        action = next((arg for arg in normalized if arg in (*REPORT_REVIEW_ACTIONS, *REPORT_SAVE_ACTIONS)), "")
        if action:
            return ("write",)
        if "network" in normalized or report_analyze_mode(normalized) == "off":
            return ("view",)
        return ("write",)

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
        parser.add_argument("--last", action="store_true", help="show the latest scan/reportable pipeline")
        parser.add_argument("--new", action="store_true", help="show facts newly introduced by the latest relevant scans")
        parser.add_argument("--accepted-first", action="store_true", help="show accepted findings before other review states")
        parser.add_argument("--candidates-first", action="store_true", help="show candidate or potential findings before other rows")
        parser.add_argument("--job", default="", help="job id or comma-separated job ids")
        parser.add_argument(
            "--pipeline",
            default="",
            help="pipeline id or comma-separated pipeline ids",
        )
        parser.add_argument("--step", default="", help="step id or comma-separated step ids")
        parser.add_argument("--name", default="", help="saved report scope name")
        parser.add_argument("--cve", default="", help="CVE selector; accepts comma-separated values and * wildcards")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--note", default="")
        parser.add_argument("--analyze", choices=REPORT_ANALYZE_CHOICES, default="passive")
        parser.add_argument("--page", choices=("true", "false"), default="false")
        parser.add_argument("--sort", choices=REPORT_SORT_CHOICES, default="finding")
        parser.add_argument("--status", choices=REPORT_STATUS_CHOICES, default="open")
        parsed = parser.parse_args(normalize_report_args(args))
        normalize_report_action(parsed)
        if parsed.last and parsed.new:
            raise ValueError("report accepts only one of --last or --new")
        if parsed.accepted_first and parsed.candidates_first:
            raise ValueError("report accepts only one of --accepted-first or --candidates-first")
        if parsed.action in REPORT_SAVE_ACTIONS:
            save_report_scope(context, parsed, action=parsed.action)
            return ()
        if parsed.action == "show":
            apply_saved_report_scope(context, parsed)

        input_findings = report_input_findings(context, input_events)
        if parsed.new and not input_findings:
            events = select_new_scope_events(context, parsed)
            context_events = select_new_context_events(context, parsed)
        else:
            events = input_findings or select_report_scope_events(context, parsed)
            context_events = [] if input_findings else select_report_context_events(context, parsed)
        if parsed.action in REPORT_REVIEW_ACTIONS:
            review_report_groups(context, parsed, events)
            return ()
        if parsed.action == "network":
            render_network_report(context, context_events, events, parsed)
            return ()
        events = [*events, *synthesize_report_findings(context, context_events, parsed)]
        render_finding_report(context, events, parsed, context_events=context_events)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete report selectors."""
        del context, args
        candidates = (
            *REPORT_ACTIONS,
            "--last",
            "--new",
            "--accepted-first",
            "--candidates-first",
            "all",
            "analyze=",
            "analyze=off",
            "analyze=passive",
            "cve=",
            "detail",
            "pipeline=",
            "job=",
            "step=",
            "limit=",
            "name=",
            "note=",
            "page=",
            "page=false",
            "page=true",
            "sort=",
            "sort=finding",
            "sort=host",
            "status=",
            "status=accepted",
            "status=all",
            "status=confirmed",
            "status=deferred",
            "status=open",
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
    return kv_to_args(normalized, REPORT_OPTION_KEYS)


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


def report_analyze_mode(normalized_args: list[str]) -> str:
    """Return the requested report analysis mode from normalized args."""
    for index, token in enumerate(normalized_args):
        if token == "--analyze" and index + 1 < len(normalized_args):
            return normalized_args[index + 1]
        if token.startswith("--analyze="):
            return token.split("=", 1)[1]
    return "passive"


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Report()
