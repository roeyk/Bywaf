"""Artifact command actions.

Implements the mutating and listing/exporting artifact operations after the
commandlet parser has converted user tokens into selector dictionaries.

Used by:
- runtime.artifact: dispatch `artifact <action>` subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext

from .action_selection import single_selected_artifact
from .display_actions import (
    artifact_provenance_events,
    cat_artifact,
    export_artifacts,
    format_artifact_detail,
    show_artifact,
    styled_artifact_value,
    write_artifact,
)
from .query import search_artifacts, select_artifacts
from .render import artifact_event_payload, format_artifact_row
from .selectors import require_values, resolve_artifact_scope, single_value

# VERIFY_PROVENANCE_TOPICS is consumed by verify_artifacts() when it reconciles
# artifact-store rows with main event DB provenance. Imported and attached
# artifacts are the lifecycle states that should have a current artifact row.
VERIFY_PROVENANCE_TOPICS = ("artifact.attached", "artifact.imported")

__all__ = [
    "artifact_provenance_events",
    "attach_artifacts",
    "cat_artifact",
    "export_artifacts",
    "format_artifact_detail",
    "import_artifacts",
    "list_artifacts",
    "remove_artifacts",
    "replace_artifact",
    "search_artifact_command",
    "show_artifact",
    "single_selected_artifact",
    "styled_artifact_value",
    "verify_artifacts",
    "write_artifact",
]


def attach_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Attach existing artifacts or import-and-attach files to provenance.

    Called by: the artifact command action dispatch for `artifact attach`.
    """
    files = selectors.get("file", [])
    artifact_selector = single_value(selectors, "artifact")
    if artifact_selector is not None and files:
        raise ValueError("artifact attach accepts artifact= or file=, not both")
    if artifact_selector is None and not files:
        raise ValueError("artifact attach requires artifact= or file=")
    if len(files) > 1 and "name" in selectors:
        raise ValueError("artifact attach name= is only valid with one file=")
    note = single_value(selectors, "note") or context.note
    scope = resolve_artifact_scope(context, selectors)
    attached: list[Artifact] = []
    if artifact_selector is not None:
        # Re-attaching keeps the artifact body immutable and creates a new
        # provenance edge to a job, pipeline, or step.
        if not any((scope.job_id, scope.pipeline_id, scope.command_run_id)):
            raise ValueError("artifact attach artifact= requires step=, pipeline=, job=, or serial=")
        store = context.artifact_store("artifact attach", read_access=True, write_access=True)
        artifact = store.get(artifact_selector)
        attached_artifact = store.attach_existing(
            artifact,
            note=note,
            job_id=scope.job_id,
            pipeline_id=scope.pipeline_id,
            command_run_id=scope.command_run_id,
        )
        context.artifacts.publish_attached(attached_artifact)
        attached.append(attached_artifact)
    else:
        for file_name in files:
            # file= is the convenience path: import the body into the artifact
            # store and attach it to the selected runtime scope in one action.
            artifact = context.artifacts.attach_file(
                Path(file_name),
                name=single_value(selectors, "name"),
                note=note,
                job_id=scope.job_id,
                pipeline_id=scope.pipeline_id,
                command_run_id=scope.command_run_id,
            )
            attached.append(artifact)
    for artifact in attached:
        context.output(format_artifact_row(artifact))


def import_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Import one or more files into the artifact DB without external provenance.

    Called by: the artifact command action dispatch for `artifact import`.
    """
    files = require_values(selectors, "file")
    if len(files) > 1 and "name" in selectors:
        raise ValueError("artifact import name= is only valid with one file=")
    events = context.event_store("artifact import")
    store = context.artifact_store("artifact import", write_access=True)
    context.audit_capability("filesystem.read")
    imported: list[Artifact] = []
    for file_name in files:
        # Import stores the body in the artifact DB but intentionally does not
        # attach it to a runtime job/pipeline/step; users can attach it later.
        artifact = store.attach_file(
            Path(file_name),
            name=single_value(selectors, "name"),
            note=single_value(selectors, "note") or context.note,
            commandlet=context.source,
        )
        imported.append(artifact)
        events.publish("artifact.imported", artifact_event_payload(artifact), "framework")
    for artifact in imported:
        context.output(format_artifact_row(artifact))


def list_artifacts(context: CommandContext, selectors: dict[str, list[str]], *, page: bool = False) -> None:
    """List artifacts matching optional selectors.

    Called by: the artifact command action dispatch for `artifact list`.
    """
    lines = [format_artifact_row(artifact) for artifact in select_artifacts(context, selectors)]
    if page and lines:
        context.page_text("\n".join(lines))
        return
    for line in lines:
        context.output(line)


def remove_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Remove selected artifacts and audit each deletion.

    Called by: the artifact command action dispatch for `artifact remove`.
    """
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    events = context.event_store("artifact")
    store = context.artifact_store("artifact", write_access=True)
    for artifact in artifacts:
        # Removal affects the artifact store first, then writes a main-DB audit
        # event preserving the runtime provenance that the row used to carry.
        store.remove(artifact)
        events.publish(
            "artifact.removed",
            artifact_event_payload(artifact),
            "framework",
            pipeline_id=artifact.pipeline_id,
            command_run_id=artifact.command_run_id,
            parent_command_run_id=artifact.parent_command_run_id,
        )
        context.output(f"removed artifact={artifact.id} artifact_id={artifact.artifact_id}")


def replace_artifact(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Replace one artifact body with a new filesystem file.

    Called by: the artifact command action dispatch for `artifact replace`.
    """
    artifact = single_selected_artifact(context, selectors, "artifact replace")
    file_name = single_value(selectors, "file")
    if file_name is None:
        raise ValueError("artifact replace requires file=")
    events = context.event_store("artifact")
    store = context.artifact_store("artifact", write_access=True)
    context.audit_capability("filesystem.read")
    replacement = store.replace_file(
        artifact,
        Path(file_name),
        name=single_value(selectors, "name"),
        note=single_value(selectors, "note") or context.note,
    )
    events.publish(
        "artifact.replaced",
        {
            "old": artifact_event_payload(artifact),
            "new": artifact_event_payload(replacement),
        },
        "framework",
        pipeline_id=replacement.pipeline_id,
        command_run_id=replacement.command_run_id,
        parent_command_run_id=replacement.parent_command_run_id,
    )
    # Replacement creates a new artifact row for immutable evidence bodies. Also
    # publish artifact.attached so result/detail views can discover the new
    # artifact through the same topic they use for ordinary attachments.
    events.publish(
        "artifact.attached",
        artifact_event_payload(replacement),
        "framework",
        pipeline_id=replacement.pipeline_id,
        command_run_id=replacement.command_run_id,
        parent_command_run_id=replacement.parent_command_run_id,
    )
    context.output(format_artifact_row(replacement))


def verify_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Verify artifact body integrity and main-DB provenance links.

    Called by: the artifact command action dispatch for `artifact verify`.
    """
    events = context.event_store("artifact")
    store = context.artifact_store("artifact", read_access=True)
    artifacts = select_artifacts(context, selectors)
    body_results = {result.artifact_id: result for result in store.verify(artifacts)}
    # Artifact bodies live in the artifact DB, but provenance is mirrored in the
    # main event DB. Verification checks both stores so export/report workflows
    # can trust the link between evidence and runtime scope.
    provenance_events = [
        event
        for topic in VERIFY_PROVENANCE_TOPICS
        for event in events.events_matching(topic=topic, limit=100000)
    ]
    provenance_by_id = {str(event.payload.get("artifact_id")): event for event in provenance_events}
    provenance_ids = set(provenance_by_id)
    matched_ids = {artifact.artifact_id for artifact in artifacts}
    for artifact in artifacts:
        result = body_results[artifact.artifact_id]
        problems = list(result.problems)
        provenance_event = provenance_by_id.get(artifact.artifact_id)
        if provenance_event is None:
            problems.append("missing main-db artifact provenance event")
        else:
            if provenance_event.payload.get("sha256") != artifact.sha256:
                problems.append("main-db sha256 mismatch")
            if provenance_event.payload.get("size") != artifact.size:
                problems.append("main-db size mismatch")
        status = "ok" if not problems else "failed"
        detail = "" if not problems else f" problems={json.dumps(problems)}"
        context.output(f"{status} artifact={artifact.id} artifact_id={artifact.artifact_id}{detail}")
    orphan_events = sorted(provenance_ids - matched_ids) if selectors else []
    for artifact_id in orphan_events:
        context.output(f"failed artifact_id={artifact_id} problems=[\"main-db provenance event has no artifact row\"]")


def search_artifact_command(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Run artifact metadata search from the namespaced artifact command.

    Called by: the artifact command action dispatch for `artifact search`.
    """
    artifacts = search_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    for artifact in artifacts:
        context.output(format_artifact_row(artifact))
