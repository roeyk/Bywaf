"""Runtime commandlet for encrypted artifacts and provenance verification."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from bywaf.artifacts import Artifact, artifact_db_path, artifact_store_for_event_store
from bywaf.events import Event
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.utils import complete_path

ARTIFACT_ACTIONS = ("attach", "list", "remove", "replace", "save", "verify")


@commandlet(
    name="artifact",
    description="Attach, list, save, replace, remove, and verify encrypted artifacts.",
    usage="artifact <attach|list|save|replace|remove|verify> [artifact=id|run=id|pipeline=id|job=id] [file=path|dir=path]",
    examples=(
        "artifact attach run=hostscanner-... file=snapshot.html file=headers.txt",
        "artifact list run=hostscanner-...",
        "artifact replace artifact=1 file=snapshot-v2.html",
        "artifact remove artifact=1",
        "artifact save artifact=1 file=snapshot.html",
        "artifact save run=hostscanner-... dir=artifacts/",
        "artifact verify pipeline=pipeline-...",
    ),
    capabilities=(
        "artifact.read",
        "artifact.write",
        "db.raw",
        "db.read:artifact.attached",
        "filesystem.read",
        "filesystem.write",
        "framework.console.output",
    ),
)
@argument("action", "artifact action", completion=CompletionSpec("choice", ARTIFACT_ACTIONS))
@argument("selector", "artifact=, run=, pipeline=, job=, file=, dir=, name=, or note=", required=False)
class ArtifactCommand(CommandletBase):
    """Manage encrypted artifacts linked to Bywaf runtime entities."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Execute one artifact action."""
        del input_events
        if not args:
            raise ValueError("artifact requires an action: attach, list, save, or verify")
        action, *tokens = args
        selectors = parse_artifact_selectors(tokens)
        match action:
            case "attach":
                attach_artifacts(context, selectors)
            case "list":
                list_artifacts(context, selectors)
            case "remove":
                remove_artifacts(context, selectors)
            case "replace":
                replace_artifact(context, selectors)
            case "save":
                save_artifacts(context, selectors)
            case "verify":
                verify_artifacts(context, selectors)
            case _:
                raise ValueError(f"unknown artifact action: {action}")
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete actions first, then selectors and filesystem paths."""
        if not args:
            return list(ARTIFACT_ACTIONS)
        if len(args) == 1 and args[0] not in ARTIFACT_ACTIONS:
            return [action for action in ARTIFACT_ACTIONS if action.startswith(prefix)]
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        if prefix.startswith("dir="):
            return [f"dir={candidate}" for candidate in complete_path(prefix.removeprefix("dir="))]
        if prefix.startswith("run="):
            return [f"run={value}" for value in run_ids(context)]
        if prefix.startswith("pipeline="):
            return [f"pipeline={value}" for value in pipeline_ids(context)]
        if prefix.startswith("job="):
            return [f"job={value}" for value in job_ids(context)]
        if prefix.startswith("artifact="):
            return [f"artifact={value}" for value in artifact_ids(context)]
        action = args[0]
        match action:
            case "attach":
                return ["run=", "pipeline=", "job=", "file=", "name=", "note="]
            case "replace":
                return ["artifact=", "file=", "note="]
            case "remove":
                return ["artifact=", "run=", "pipeline=", "job="]
            case "list" | "verify":
                return ["artifact=", "run=", "pipeline=", "job="]
            case "save":
                return ["artifact=", "run=", "pipeline=", "job=", "file=", "dir="]
            case _:
                return list(ARTIFACT_ACTIONS)


def parse_artifact_selectors(tokens: list[str]) -> dict[str, list[str]]:
    """Parse artifact key=value selectors, preserving repeated file= values."""
    selectors: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if "=" not in token:
            raise ValueError(f"invalid artifact selector: {token}")
        key, value = token.split("=", 1)
        if key == "note":
            value = " ".join([value, *tokens[index + 1:]]).strip()
            index = len(tokens)
        else:
            index += 1
        if key not in {"artifact", "run", "pipeline", "job", "file", "dir", "name", "note"}:
            raise ValueError(f"unknown artifact selector: {key}")
        if not value:
            raise ValueError(f"artifact selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
    return selectors


def attach_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Attach one or more files to a run, pipeline, or job."""
    files = require_values(selectors, "file")
    if len(files) > 1 and "name" in selectors:
        raise ValueError("artifact attach name= is only valid with one file=")
    attached: list[Artifact] = []
    note = single_value(selectors, "note") or context.note
    for file_name in files:
        artifact = context.artifacts.attach_file(
            Path(file_name),
            name=single_value(selectors, "name"),
            note=note,
            job_id=single_value(selectors, "job"),
            pipeline_id=single_value(selectors, "pipeline"),
            command_run_id=single_value(selectors, "run"),
        )
        attached.append(artifact)
    for artifact in attached:
        context.output(format_artifact_row(artifact))


def list_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """List artifacts matching optional selectors."""
    for artifact in select_artifacts(context, selectors):
        context.output(format_artifact_row(artifact))


def save_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> None:
    """Save selected encrypted artifacts back to the filesystem."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    output_file = single_value(selectors, "file")
    output_dir = single_value(selectors, "dir")
    if output_file and output_dir:
        raise ValueError("artifact save accepts file= or dir=, not both")
    if output_file:
        if len(artifacts) != 1:
            raise ValueError("artifact save file= matched multiple artifacts; use dir= to save a set")
        write_artifact(context, artifacts[0], Path(output_file).expanduser())
        return
    if output_dir is None:
        raise ValueError("artifact save requires file= for one artifact or dir= for multiple artifacts")
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
    db = context.require_db("artifact")
    store = artifact_store_for_event_store(db)
    context.audit_capability("artifact.write")
    for artifact in artifacts:
        store.remove(artifact)
        db.publish(
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
    db = context.require_db("artifact")
    store = artifact_store_for_event_store(db)
    context.audit_capability("filesystem.read")
    context.audit_capability("artifact.write")
    replacement = store.replace_file(artifact, Path(file_name), note=single_value(selectors, "note") or context.note)
    db.publish(
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
    db.publish(
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
    db = context.require_db("artifact")
    store = artifact_store_for_event_store(db)
    artifacts = select_artifacts(context, selectors)
    body_results = {result.artifact_id: result for result in store.verify(artifacts)}
    attached_events = db.events_matching(topic="artifact.attached", limit=100000)
    attached_by_id = {str(event.payload.get("artifact_id")): event for event in attached_events}
    attached_ids = set(attached_by_id)
    matched_ids = {artifact.artifact_id for artifact in artifacts}
    for artifact in artifacts:
        result = body_results[artifact.artifact_id]
        problems = list(result.problems)
        attached_event = attached_by_id.get(artifact.artifact_id)
        if attached_event is None:
            problems.append("missing main-db artifact.attached event")
        else:
            if attached_event.payload.get("sha256") != artifact.sha256:
                problems.append("main-db sha256 mismatch")
            if attached_event.payload.get("size") != artifact.size:
                problems.append("main-db size mismatch")
        status = "ok" if not problems else "failed"
        detail = "" if not problems else f" problems={json.dumps(problems)}"
        context.output(f"{status} artifact={artifact.id} artifact_id={artifact.artifact_id}{detail}")
    orphan_events = sorted(attached_ids - matched_ids) if selectors else []
    for artifact_id in orphan_events:
        context.output(f"failed artifact_id={artifact_id} problems=[\"main-db event has no artifact row\"]")


def select_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> list[Artifact]:
    """Return artifacts selected by artifact=, run=, pipeline=, or job=."""
    db = context.require_db("artifact")
    context.audit_capability("artifact.read")
    store = artifact_store_for_event_store(db)
    artifact_id = single_value(selectors, "artifact")
    if artifact_id is not None:
        return [store.get(artifact_id)]
    return store.list(
        job_id=single_value(selectors, "job"),
        pipeline_id=single_value(selectors, "pipeline"),
        command_run_id=single_value(selectors, "run"),
    )


def single_selected_artifact(context: CommandContext, selectors: dict[str, list[str]], action: str) -> Artifact:
    """Return exactly one selected artifact for mutation commands."""
    artifacts = select_artifacts(context, selectors)
    if not artifacts:
        raise ValueError(f"{action} matched no artifacts")
    if len(artifacts) > 1:
        raise ValueError(f"{action} matched multiple artifacts; use artifact=<id>")
    return artifacts[0]


def artifact_event_payload(artifact: Artifact) -> dict[str, object]:
    """Return public artifact metadata for audit events."""
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_row_id": artifact.id,
        "name": artifact.name,
        "content_type": artifact.content_type,
        "sha256": artifact.sha256,
        "size": artifact.size,
        "created_at": artifact.created_at,
        "source_path": artifact.source_path,
        "commandlet": artifact.commandlet,
        "job_id": artifact.job_id,
        "pipeline_id": artifact.pipeline_id,
        "command_run_id": artifact.command_run_id,
        "parent_command_run_id": artifact.parent_command_run_id,
        "note": artifact.note,
    }


def write_artifact(context: CommandContext, artifact: Artifact, path: Path) -> None:
    """Write one artifact body to disk and audit the save."""
    path.parent.mkdir(parents=True, exist_ok=True)
    context.audit_capability("filesystem.write")
    path.write_bytes(artifact.body)
    db = context.require_db("artifact")
    db.publish(
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
    context.output(f"saved artifact={artifact.id} file={path}")


def require_values(selectors: dict[str, list[str]], name: str) -> list[str]:
    """Return all selector values for a required key."""
    values = selectors.get(name, [])
    if not values:
        raise ValueError(f"artifact {name}= is required")
    return values


def single_value(selectors: dict[str, list[str]], name: str) -> str | None:
    """Return one selector value and reject ambiguous repeats."""
    values = selectors.get(name, [])
    if len(values) > 1:
        raise ValueError(f"artifact selector {name}= may only appear once")
    return values[0] if values else None


def format_artifact_row(artifact: Artifact) -> str:
    """Return one timestamp-first artifact listing row."""
    return (
        f"{artifact.created_at} artifact={artifact.id} artifact_id={artifact.artifact_id} "
        f"name={artifact.name} size={artifact.size} sha256={artifact.sha256} "
        f"job={artifact.job_id or ''} pipeline={artifact.pipeline_id or ''} run={artifact.command_run_id or ''}"
    )


def safe_artifact_filename(artifact: Artifact) -> str:
    """Build a stable export filename for a stored artifact."""
    clean = "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in artifact.name).strip("_")
    return f"{artifact.id}-{clean or artifact.artifact_id}"


def run_ids(context: CompletionContext) -> list[str]:
    """Return command-run IDs for completion."""
    if context.db is None:
        return []
    return [str(row["command_run_id"]) for row in context.db.runs()]


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return [str(row["pipeline_id"]) for row in context.db.pipelines()]


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    if context.db is None:
        return []
    return [str(row["id"]) for row in context.db.jobs()]


def artifact_ids(context: CompletionContext) -> list[str]:
    """Return artifact row IDs for completion when the store is unlocked."""
    if context.db is None or context.db.passphrase is None:
        return []
    if not artifact_db_path(context.db.path).exists():
        return []
    try:
        store = artifact_store_for_event_store(context.db)
    except RuntimeError:
        return []
    return [str(artifact.id) for artifact in store.list()]


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return ArtifactCommand()
