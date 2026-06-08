"""Runtime bundle commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Groups runtime entities and artifacts into named bundles.

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
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.plugins.runtime.bundle_actions import (
    add_bundle_item,
    bundle_action_handlers,
    bundle_completion_selectors,
    complete_bundle_action,
    completion_values,
    create_bundle,
    export_bundle,
    list_bundles,
    seal_bundle,
    show_bundle,
    verify_bundle,
)
from bywaf.plugins.runtime.bundle_content import (
    artifact_record,
    bundle_manifest,
    resolve_bundle_content,
    resolve_job_selector,
    resolve_pipeline_selector,
    resolve_run_selector,
    selected_artifacts,
)
from bywaf.plugins.runtime.bundle_model import (
    BUNDLE_ACTIONS,
    BUNDLE_CONTENT_KINDS,
    Bundle,
    canonical_json,
    first_content_kind,
    parse_bundle_selectors,
    require_selector,
    split_csv,
)
from bywaf.plugins.runtime.bundle_state import all_bundles, bundle_by_name, require_bundle

__all__ = [
    "BUNDLE_ACTIONS",
    "BUNDLE_CONTENT_KINDS",
    "Bundle",
    "BundleCommand",
    "add_bundle_item",
    "all_bundles",
    "artifact_record",
    "bundle_action_handlers",
    "bundle_by_name",
    "bundle_completion_selectors",
    "bundle_manifest",
    "canonical_json",
    "completion_values",
    "create_bundle",
    "export_bundle",
    "first_content_kind",
    "list_bundles",
    "parse_bundle_selectors",
    "plugin",
    "require_bundle",
    "require_selector",
    "resolve_bundle_content",
    "resolve_job_selector",
    "resolve_pipeline_selector",
    "resolve_run_selector",
    "seal_bundle",
    "selected_artifacts",
    "show_bundle",
    "split_csv",
    "verify_bundle",
]


@commandlet(
    name="bundle",
    description="Create, populate, sign, verify, and export evidence bundles.",
    usage="bundle <create|add|list|show|seal|verify|export> name=<bundle> [audit|evidence|reports] [file=<path>]",
    examples=(
        "bundle create name=client-a",
        "bundle add name=client-a audit since=20260501 until=20260519",
        "bundle add name=client-a evidence commandlet=nikto,webfin",
        "bundle seal name=client-a --sign key=firm-evidence",
        "bundle verify name=client-a",
        "bundle export name=client-a file=client-a.bundle.json",
    ),
)
@argument("action", "bundle action", completion=CompletionSpec("choice", BUNDLE_ACTIONS))
class BundleCommand(CommandletBase):
    """Manage auditable evidence bundles."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify bundle inspection separately from bundle mutation."""
        action = args[0] if args else ""
        return ("view",) if action in {"list", "show", "verify"} else ("write",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Dispatch one bundle action."""
        del input_events
        if not args:
            raise ValueError("bundle requires an action")
        action, *tokens = args
        handlers = bundle_action_handlers()
        if action not in handlers:
            raise ValueError(f"unknown bundle action: {action}")
        handlers[action](context, tokens)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete bundle actions, content kinds, file paths, and key names."""
        return complete_bundle_action(context, args, prefix, BUNDLE_ACTIONS)


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return BundleCommand()
