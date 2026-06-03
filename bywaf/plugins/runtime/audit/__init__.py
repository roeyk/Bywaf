"""Runtime audit commandlet.

Provides bundled commandlet metadata and dispatch for audit display/export.
Inventory, selector, and exporter logic live in focused helper modules.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch.
- report/artifact helpers: import stable audit selector utilities."""

from __future__ import annotations

import json
from argparse import Namespace
from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
    option,
)
from bywaf.utils import complete_path

from . import export as audit_export_module
from .common import AUDIT_ACTIONS, AUDIT_FORMATS, AUDIT_LIST_TARGETS, AuditActionHandler
from .export import event_record, export_events
from .inventory import capability_inventory_rows, format_capability_inventory
from .policy_report import format_policy_decisions, policy_decision_rows, policy_selector_completion_candidates
from .selectors import (
    parse_compact_time as parse_compact_time,
    parse_list_selectors,
    parse_selectors,
    require_selector,
    resolve_pipeline_selector as resolve_pipeline_selector,
    resolve_run_selector as resolve_run_selector,
    selected_events,
)

# Compatibility for tests and callers that patch `bywaf.plugins.runtime.audit.shutil`.
shutil = audit_export_module.shutil


@commandlet(
    name="audit",
    description="Show or export the SQLite-backed audit log.",
    usage="audit <show|export> [file=<path>] [topic=<topic>|step=<id>|pipeline=<id>|job=<id-or-serial>|serial=<id>]",
    examples=(
        "audit list capabilities",
        "audit list capabilities plugin=nikto",
        "audit list policy",
        "audit list policy decision=warn",
        "audit list policy plugin=hostscanner target=198.51.100.10",
        "audit show topic=plugin.capability.used",
        "audit show step=1",
        "audit show serial=hostscanner-...",
        "audit show since=20260517 until=20260518",
        "audit export file=audit.jsonl",
        "audit export file=audit.sqlite3 --format sqlite",
    ),
)
@option("format", "export format", "auto", choices=("auto", *AUDIT_FORMATS))
@option("limit", "maximum events to show or export", "1000")
@argument("action", "audit operation", completion=CompletionSpec("choice", AUDIT_ACTIONS))
@argument("selector", "file=, topic=, step=, pipeline=, or job= selector", required=False)
class Audit(CommandletBase):
    """Provide first-class access to Bywaf's event audit trail."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one audit operation."""
        del input_events
        parser = self.parser()
        parser.add_argument("action", choices=AUDIT_ACTIONS)
        parser.add_argument("selectors", nargs="*")
        parser.add_argument("--format", default="auto", choices=("auto", *AUDIT_FORMATS))
        parser.add_argument("--encrypt", action="store_true")
        parser.add_argument("--limit", type=int, default=1000)
        parsed = parser.parse_intermixed_args(args)
        selectors = parse_list_selectors(parsed.selectors) if parsed.action == "list" else parse_selectors(parsed.selectors)
        audit_action_handlers()[parsed.action](context, parsed, selectors)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete audit actions, list targets, selectors, and filesystem paths."""
        if not args:
            return list(AUDIT_ACTIONS)
        if len(args) == 1 and args[0] not in AUDIT_ACTIONS:
            return list(AUDIT_ACTIONS)
        if args and args[0] == "list":
            if len(args) == 1:
                return list(AUDIT_LIST_TARGETS)
            if len(args) >= 2 and args[1] == "policy":
                return policy_selector_completion_candidates(context, prefix)
            return ["plugin=", "decision=", "target=", "step=", "pipeline=", "job=", "serial=", "since=", "until="]
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        return ["file=", "topic=", "step=", "pipeline=", "job=", "serial=", "since=", "until="]


def audit_action_handlers() -> dict[str, AuditActionHandler]:
    """Return audit action handlers keyed by action name."""
    return {
        "export": export_audit_action,
        "list": list_audit_action,
        "show": show_audit_action,
    }


def show_audit_action(context: CommandContext, parsed: Namespace, selectors: dict[str, str]) -> None:
    """Print selected audit events."""
    for event in selected_events(context, selectors, parsed.limit):
        context.output(json.dumps(event_record(event), sort_keys=True))


def export_audit_action(context: CommandContext, parsed: Namespace, selectors: dict[str, str]) -> None:
    """Export selected audit events."""
    path = require_selector(selectors, "file")
    export_events(
        context,
        Path(path).expanduser(),
        selectors,
        parsed.format,
        parsed.limit,
        encrypt=parsed.encrypt,
    )


def list_audit_action(context: CommandContext, parsed: Namespace, selectors: dict[str, str]) -> None:
    """Print audit inventory reports."""
    del parsed
    target = selectors.pop("_target", "")
    if target == "capabilities":
        unsupported = set(selectors) - {"plugin"}
        if unsupported:
            raise ValueError(f"unsupported audit capability selector: {sorted(unsupported)[0]}")
        rows = capability_inventory_rows(context, plugin_filter=selectors.get("plugin"))
        context.output(format_capability_inventory(rows))
        return
    if target == "policy":
        context.output(format_policy_decisions(policy_decision_rows(context, selectors)))
        return
    raise ValueError("audit list supports: capabilities, policy")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Audit()
