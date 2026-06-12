"""Artifact display, preview, and export actions.

Called by: `runtime.artifact.actions` compatibility exports and the bundled
`artifact` command dispatch table for show/cat/export behavior.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

from pathlib import Path

from bywaf.artifacts import Artifact
from bywaf.plugin import CommandContext
from bywaf.runtime_display import command_context_style_getter
from bywaf.style import styled_subject_text

from .action_selection import single_selected_artifact
from .preview import artifact_cat_limit, artifact_preview_suffix, format_artifact_preview, pop_selector_flag
from .query import select_artifacts
from .render import safe_artifact_filename
from .selectors import single_value


def show_artifact(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Show a readable detail view for exactly one artifact.

    Called by: the artifact command dispatch table for `artifact show`.
    """
    artifact = single_selected_artifact(context, selectors, "artifact show")
    context.output(format_artifact_detail(context, artifact))


def cat_artifact(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Render one artifact body as text or hex.

    Called by: the artifact command dispatch table for `artifact cat`.
    """
    artifact = single_selected_artifact(context, selectors, "artifact cat")
    limit = artifact_cat_limit(selectors)
    encoding = single_value(selectors, "encoding") or "utf-8"
    preview = format_artifact_preview(artifact, limit=limit, encoding=encoding)
    # `page` is consumed by page_text below; removing it keeps later selector
    # validation from treating it as an artifact filter.
    pop_selector_flag(selectors, "page")
    context.page_text(preview, suffix=artifact_preview_suffix(artifact))


def export_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Export selected artifacts back to the filesystem.

    Called by: the artifact command dispatch table for `artifact export`.
    """
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
        # file= is intentionally single-artifact so a selector typo cannot
        # silently overwrite one path with several artifact bodies.
        write_artifact(context, artifacts[0], Path(output_file).expanduser())
        return
    if output_dir is None:
        raise ValueError("artifact export requires file= for one artifact or dir= for multiple artifacts")
    directory = Path(output_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        write_artifact(context, artifact, directory / safe_artifact_filename(artifact))


def format_artifact_detail(context: CommandContext, artifact: Artifact) -> str:
    """Return a compact artifact detail block with provenance and next commands.

    Called by: `show_artifact()`.
    """
    # The top block is a stable operator summary; optional provenance fields are
    # appended only when the artifact carries those runtime identifiers.
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
    # These commands are intentionally copy-pasteable follow-ups for the exact
    # artifact being viewed.
    commands = [
        styled_artifact_value(context, "command_line", f"artifact cat artifact={artifact.id}"),
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
    """Return an artifact detail value using the operator's subject style.

    Called by: artifact detail/export display helpers.
    """
    return styled_subject_text(command_context_style_getter(context), subject, value)


def artifact_provenance_events(context: CommandContext, artifact: Artifact) -> list:
    """Return main-DB provenance events for one artifact.

    Called by: `format_artifact_detail()`.
    """
    events = context.event_store("artifact show")
    matches = []
    for topic in ("artifact.attached", "artifact.imported", "artifact.replaced", "artifact.exported", "artifact.removed"):
        for event in events.events_matching(topic=topic, limit=100000):
            # Match both durable artifact serials and legacy row-id references
            # so detail views keep working across artifact replacement/import
            # events.
            if str(event.payload.get("artifact_id") or "") == artifact.artifact_id:
                matches.append(event)
            elif str(event.payload.get("artifact_row_id") or "") == str(artifact.id):
                matches.append(event)
    return sorted(matches, key=lambda event: event.id or 0)


def write_artifact(context: CommandContext, artifact: Artifact, path: Path) -> None:
    """Write one artifact body to disk and audit the export.

    Called by: `export_artifacts()` after selector validation.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    context.audit_capability("filesystem.write")
    path.write_bytes(artifact.body)
    # Exporting an artifact is a side effect outside the database, so write a
    # main-store audit event that ties the filesystem path back to the artifact.
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
