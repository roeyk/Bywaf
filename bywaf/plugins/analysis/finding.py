"""Finding review commandlet.

Provides short operator actions for confirming and unconfirming report rows
without making `report` own all finding workflow verbs.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute finding confirmation actions through normal commandlet dispatch."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet, option
from bywaf.plugins.analysis.finding_report import REPORT_FINDING_TOPICS
from bywaf.plugins.analysis.report import REPORT_OPTION_KEYS, REPORT_SORT_CHOICES, REPORT_STATUS_CHOICES
from bywaf.plugins.analysis.report.events import select_report_scope_events
from bywaf.plugins.analysis.report.review import review_report_groups
from bywaf.plugin import kv_to_args

FINDING_ACTIONS = ("confirm", "unconfirm")
FINDING_OPTION_KEYS = REPORT_OPTION_KEYS


@commandlet(
    name="finding",
    description="Confirm or unconfirm grouped finding rows from a report scope.",
    usage="finding confirm|unconfirm <index-range|all> [pipeline=<ids>] [job=<ids>] [step=<ids>] [status=<filter>] [cve=<id|pattern>] [note=<text>]",
    examples=(
        "finding confirm 1 pipeline=7 note=validated with curl",
        "finding confirm all cve=CVE-2021-*",
        "finding confirm all status=unreviewed",
        "finding unconfirm 1 status=confirmed note=retest no longer reproduces",
    ),
)
@option("job", "job id or comma-separated job ids", completion="job")
@option("pipeline", "pipeline id or comma-separated pipeline ids", completion="pipeline")
@option("step", "step id or comma-separated step ids", completion="step")
@option("cve", "CVE selector; accepts comma-separated values and * wildcards")
@option("limit", "maximum events to inspect", "1000")
@option("note", "operator review note")
@option("sort", "report grouping used for row numbering", "finding", REPORT_SORT_CHOICES)
@option("status", "finding review status filter", "open", REPORT_STATUS_CHOICES)
class Finding(CommandletBase):
    """Apply operator review decisions to grouped finding rows."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Confirm or unconfirm selected finding rows."""
        parser = self.parser()
        parser.usage = self.spec.usage
        parser.add_argument("action", choices=FINDING_ACTIONS)
        parser.add_argument("selection")
        parser.add_argument("--job", default="")
        parser.add_argument("--pipeline", default="")
        parser.add_argument("--step", default="")
        parser.add_argument("--cve", default="")
        parser.add_argument("--limit", type=int, default=1000)
        parser.add_argument("--note", default="")
        parser.add_argument("--sort", choices=REPORT_SORT_CHOICES, default="finding")
        parser.add_argument("--status", choices=REPORT_STATUS_CHOICES, default="")
        parsed = parser.parse_args(normalize_finding_args(args))
        if not parsed.status:
            parsed.status = "confirmed" if parsed.action == "unconfirm" else "open"
        events = [event for event in input_events if event.topic in REPORT_FINDING_TOPICS] or select_report_scope_events(context, parsed)
        review_report_groups(context, parsed, events, source="finding")
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete finding action selectors."""
        del context, args
        candidates = (
            "confirm",
            "unconfirm",
            "all",
            "cve=",
            "pipeline=",
            "job=",
            "step=",
            "limit=",
            "note=",
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


def normalize_finding_args(args: list[str]) -> list[str]:
    """Normalize finding key=value selectors, letting final note= consume trailing text."""
    normalized: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("note="):
            note = " ".join([token.split("=", 1)[1], *args[index + 1:]]).strip()
            if not note:
                raise ValueError("finding note= requires a value")
            normalized.extend(["--note", note])
            break
        normalized.append(token)
        index += 1
    return kv_to_args(normalized, FINDING_OPTION_KEYS)


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return Finding()
