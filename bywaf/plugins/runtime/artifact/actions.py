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
from bywaf.runtime_display import command_context_style_getter
from bywaf.style import styled_subject_text

from .query import search_artifacts, select_artifacts
from .render import artifact_event_payload, format_artifact_row, safe_artifact_filename
from .selectors import require_values, resolve_artifact_scope, single_value


def attach_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Attach existing artifacts or import-and-attach files to provenance."""
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
    """Import one or more files into the artifact DB without external provenance."""
    files = require_values(selectors, "file")
    if len(files) > 1 and "name" in selectors:
        raise ValueError("artifact import name= is only valid with one file=")
    events = context.event_store("artifact import")
    store = context.artifact_store("artifact import", write_access=True)
    context.audit_capability("filesystem.read")
    imported: list[Artifact] = []
    for file_name in files:
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
    """List artifacts matching optional selectors."""
    lines = [format_artifact_row(artifact) for artifact in select_artifacts(context, selectors)]
    if page and lines:
        context.page_text("\n".join(lines))
        return
    for line in lines:
        context.output(line)


def show_artifact(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Show a readable detail view for exactly one artifact."""
    artifact = single_selected_artifact(context, selectors, "artifact show")
    context.output(format_artifact_detail(context, artifact))


def export_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Export selected artifacts back to the filesystem."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    output_file = single_value(selectors, "file")
    output_dir = single_value(selectors, "dir")
    if output_file and output_dir:
        raise ValueError("artifact export accepts file= or dir=, not both")
    if output_file:
        if len(artifacts) != 1:
            raise ValueError("artifact export file= matched multiple artifacts; use dir= to export a set")
        write_artifact(context, artifacts[0], Path(output_file).expanduser())
        return
    if output_dir is None:
        raise ValueError("artifact export requires file= for one artifact or dir= for multiple artifacts")
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        write_artifact(context, artifact, directory / safe_artifact_filename(artifact))


def remove_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Remove selected artifacts and audit each deletion."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    events = context.event_store("artifact")
    store = context.artifact_store("artifact", write_access=True)
    for artifact in artifacts:
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
    """Replace one artifact body with a new filesystem file."""
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
    """Verify artifact body integrity and main-DB provenance links."""
    events = context.event_store("artifact")
    store = context.artifact_store("artifact", read_access=True)
    artifacts = select_artifacts(context, selectors)
    body_results = {result.artifact_id: result for result in store.verify(artifacts)}
    # Artifact bodies live in the artifact DB, but provenance is mirrored in the
    # main event DB. Verification checks both stores so export/report workflows
    # can trust the link between evidence and runtime scope.
    provenance_events = [
        *events.events_matching(topic="artifact.attached", limit=100000),
        *events.events_matching(topic="artifact.imported", limit=100000),
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


def single_selected_artifact(context: CommandContext, selectors: dict[str, list[str]], action: str) -> Artifact:
    """Return exactly one selected artifact for mutation commands."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        raise ValueError(f"{action} matched no artifacts")
    if len(artifacts) > 1:
        raise ValueError(f"{action} matched multiple artifacts; use artifact=<id>")
    return artifacts[0]


def format_artifact_detail(context: CommandContext, artifact: Artifact) -> str:
    """Return a compact artifact detail block with provenance and next commands."""
    rows = [
        ("artifact", styled_artifact_value(context, "artifact", artifact.id)),
        ("serial", styled_artifact_value(context, "serial", artifact.artifact_id)),
        ("name", artifact.name),
        ("content type", artifact.content_type),
        ("size", str(artifact.size)),
        ("sha256", styled_artifact_value(context, "hash", artifact.sha256)),
        ("created", artifact.created_at),
    ]
    if artifact.source_path:
        rows.append(("source path", styled_artifact_value(context, "path", artifact.source_path)))
    if artifact.commandlet:
        rows.append(("commandlet", artifact.commandlet))
    if artifact.job_id:
        rows.append(("job", styled_artifact_value(context, "job", artifact.job_id)))
    if artifact.pipeline_id:
        rows.append(("pipeline", styled_artifact_value(context, "pipeline", artifact.pipeline_id)))
    if artifact.command_run_id:
        rows.append(("step", styled_artifact_value(context, "step", artifact.command_run_id)))
    if artifact.parent_command_run_id:
        rows.append(("parent step", artifact.parent_command_run_id))
    if artifact.note:
        rows.append(("note", artifact.note))
    lines = ["Artifact summary", *[f"  {label}: {value}" for label, value in rows]]
    commands = [
        styled_artifact_value(context, "command_line", f"artifact export artifact={artifact.id} file={safe_artifact_filename(artifact)}"),
        styled_artifact_value(context, "command_line", f"artifact verify artifact={artifact.id}"),
        styled_artifact_value(context, "command_line", f"artifact list artifact={artifact.id}"),
    ]
    if artifact.command_run_id:
        commands.append(styled_artifact_value(context, "command_line", f"step {artifact.command_run_id}"))
    if artifact.pipeline_id:
        commands.append(styled_artifact_value(context, "command_line", f"pipeline {artifact.pipeline_id}"))
    if artifact.job_id:
        commands.append(styled_artifact_value(context, "command_line", f"job {artifact.job_id}"))
    lines.append("")
    lines.append("inspect further with: " + "; ".join(commands))
    provenance = artifact_provenance_events(context, artifact)
    if provenance:
        lines.append("")
        lines.append("Provenance events")
        for event in provenance[:8]:
            event_id = styled_artifact_value(context, "event", event.id)
            lines.append(f"  {event_id}: {event.topic} source={event.source}")
    return "\n".join(lines)


def styled_artifact_value(context: CommandContext, subject: str, value: object) -> str:
    """Return an artifact detail value using the operator's subject style."""
    return styled_subject_text(command_context_style_getter(context), subject, value)


def artifact_provenance_events(context: CommandContext, artifact: Artifact) -> list:
    """Return main-DB provenance events for one artifact."""
    events = context.event_store("artifact show")
    matches = []
    for topic in ("artifact.attached", "artifact.imported", "artifact.replaced", "artifact.exported", "artifact.removed"):
        for event in events.events_matching(topic=topic, limit=100000):
            if str(event.payload.get("artifact_id") or "") == artifact.artifact_id:
                matches.append(event)
            elif str(event.payload.get("artifact_row_id") or "") == str(artifact.id):
                matches.append(event)
    return sorted(matches, key=lambda event: event.id or 0)


def write_artifact(context: CommandContext, artifact: Artifact, path: Path) -> None:
    """Write one artifact body to disk and audit the export."""
    path.parent.mkdir(parents=True, exist_ok=True)
    context.audit_capability("filesystem.write")
    path.write_bytes(artifact.body)
    context.event_store("artifact").publish(
        "artifact.exported",
        {
            "artifact_id": artifact.artifact_id,
            "artifact_row_id": artifact.id,
            "file": str(path),
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "framework",
        pipeline_id=artifact.pipeline_id,
        command_run_id=artifact.command_run_id,
        parent_command_run_id=artifact.parent_command_run_id,
    )
    context.output(f"exported artifact={artifact.id} file={path}")


def search_artifact_command(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Run artifact metadata search from the namespaced artifact command."""
    artifacts = search_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    for artifact in artifacts:
        context.output(format_artifact_row(artifact))
