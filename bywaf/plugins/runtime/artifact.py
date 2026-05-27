"""Runtime artifact commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Lists, shows, and exports artifacts recorded by commandlets.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from bywaf.artifacts import Artifact, artifact_db_path, artifact_store_for_event_store
from bywaf.events import Event
from bywaf.plugins.runtime.audit import parse_compact_time
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

ARTIFACT_ACTIONS = ("attach", "export", "import", "list", "remove", "replace", "search", "verify")
SEARCH_FLAGS = ("--regexp",)
SEARCH_FIELDS = ("name", "filename", "note", "content")
ArtifactActionHandler = Callable[[CommandContext, list[str]], None]


@commandlet(
    name="artifact",
    description="Import, attach, list, export, replace, remove, and verify artifacts.",
    usage="artifact <import|attach|list|export|replace|remove|search|verify> [serial=id|artifact=id|step=id|pipeline=id|job=id|topic=name] [file=path|dir=path]",
    examples=(
        "artifact attach step=1 file=snapshot.html name='Landing page'",
        "artifact attach serial=run-... file=snapshot.html",
        "artifact import file=snapshot.html name='Landing page'",
        "artifact attach artifact=1 step=1",
        "artifact list step=1",
        "artifact search --regexp note='login|cookie'",
        "artifact replace artifact=1 file=snapshot-v2.html",
        "artifact remove artifact=1",
        "artifact export artifact=1 file=snapshot.html",
        "artifact export step=1 dir=artifacts/",
        "artifact verify pipeline=1",
    ),
    capabilities=(
        "artifact.read",
        "artifact.write",
        "db.read:artifact.attached",
        "filesystem.read",
        "filesystem.write",
        "framework.console.output",
    ),
)
@argument("action", "artifact action", completion=CompletionSpec("choice", ARTIFACT_ACTIONS))
@argument("selector", "serial=, artifact=, step=, pipeline=, job=, file=, dir=, name=, or note=", required=False)
class ArtifactCommand(CommandletBase):
    """Manage artifacts linked to Bywaf runtime entities."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Execute one artifact action."""
        del input_events
        if not args:
            raise ValueError("artifact requires an action: import, attach, export, list, remove, replace, search, or verify")
        action, *tokens = args
        handler = artifact_action_handlers().get(action)
        if handler is None:
            raise ValueError(f"unknown artifact action: {action}")
        handler(context, tokens)
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
        if prefix.startswith("step="):
            return [f"step={value}" for value in run_ids(context)]
        if prefix.startswith("pipeline="):
            return [f"pipeline={value}" for value in pipeline_ids(context)]
        if prefix.startswith("job="):
            return [f"job={value}" for value in job_ids(context)]
        if prefix.startswith("artifact="):
            return [f"artifact={value}" for value in artifact_ids(context)]
        if prefix.startswith("serial="):
            return [f"serial={value}" for value in serial_ids(context)]
        if prefix.startswith("topic="):
            return [f"topic={value}" for value in artifact_topics(context)]
        return artifact_completion_selectors().get(args[0], list(ARTIFACT_ACTIONS))


def artifact_action_handlers() -> dict[str, ArtifactActionHandler]:
    """Return artifact action handlers keyed by action name."""
    return {
        "attach": attach_artifacts_command,
        "list": list_artifacts_command,
        "import": import_artifacts_command,
        "remove": remove_artifacts_command,
        "replace": replace_artifact_command,
        "export": export_artifacts_command,
        "search": search_artifact_command,
        "verify": verify_artifacts_command,
    }


def artifact_completion_selectors() -> dict[str, list[str]]:
    """Return selector completions keyed by artifact action."""
    return {
        "attach": ["artifact=", "serial=", "step=", "pipeline=", "job=", "file=", "name=", "note="],
        "import": ["file=", "name=", "note="],
        "replace": ["artifact=", "file=", "name=", "note="],
        "remove": ["artifact=", "serial=", "step=", "pipeline=", "job="],
        "list": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "--page"],
        "verify": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic="],
        "export": ["artifact=", "serial=", "step=", "pipeline=", "job=", "topic=", "file=", "dir="],
        "search": [
            "name=",
            "filename=",
            "note=",
            "content=",
            "serial=",
            "--regexp",
            "artifact=",
            "step=",
            "pipeline=",
            "job=",
            "since=",
            "until=",
        ],
    }


def attach_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact attach."""
    attach_artifacts(context, parse_artifact_selectors(tokens))


def import_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact import."""
    import_artifacts(context, parse_artifact_selectors(tokens))


def list_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact list."""
    selectors = parse_artifact_selectors(tokens, allow_page=True)
    list_artifacts(context, selectors, page=pop_page_flag(selectors))


def remove_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact remove."""
    remove_artifacts(context, parse_artifact_selectors(tokens))


def replace_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact replace."""
    replace_artifact(context, parse_artifact_selectors(tokens))


def export_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact export."""
    export_artifacts(context, parse_artifact_selectors(tokens))


def verify_artifacts_command(context: CommandContext, tokens: list[str]) -> None:
    """Parse and run artifact verify."""
    verify_artifacts(context, parse_artifact_selectors(tokens))


@commandlet(
    name="search",
    description="Search artifact metadata and text content.",
    usage="search [--regexp] <name=text|filename=text|note=text|content=text|serial=id> [artifact=id|step=id|pipeline=id|job=id] [since=time|until=time]",
    examples=(
        "search name=landing",
        "search --regexp filename='.*\\.png'",
        "search serial=pipeline-...",
        "search step=1 content=csrf",
    ),
    capabilities=(
        "artifact.read",
        "framework.console.output",
    ),
)
@argument("query", "name=, filename=, note=, or content= query text", required=False)
@argument("regexp", "--regexp treats query values as Python regular expressions", required=False, completion=CompletionSpec("choice", SEARCH_FLAGS))
class SearchCommand(CommandletBase):
    """Search artifact metadata without changing artifacts."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Search artifact metadata and print matching artifact rows."""
        del input_events
        selectors = parse_search_selectors(args)
        if not any(field in selectors for field in SEARCH_FIELDS) and "serial" not in selectors:
            raise ValueError("search requires name=, filename=, note=, content=, or serial=")
        artifacts = search_artifacts(context, selectors)
        if not artifacts:
            context.output("no artifacts matched")
            return ()
        for artifact in artifacts:
            context.output(format_artifact_row(artifact))
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete search selectors, scopes, and runtime entity ids."""
        del args
        if prefix.startswith("step="):
            return [f"step={value}" for value in run_ids(context)]
        if prefix.startswith("pipeline="):
            return [f"pipeline={value}" for value in pipeline_ids(context)]
        if prefix.startswith("job="):
            return [f"job={value}" for value in job_ids(context)]
        if prefix.startswith("artifact="):
            return [f"artifact={value}" for value in artifact_ids(context)]
        if prefix.startswith("serial="):
            return [f"serial={value}" for value in serial_ids(context)]
        return ["name=", "filename=", "note=", "content=", "serial=", "--regexp", "artifact=", "step=", "pipeline=", "job=", "since=", "until="]


def parse_artifact_selectors(tokens: list[str], *, allow_page: bool = False) -> dict[str, list[str]]:
    """Parse artifact key=value selectors, preserving repeated file= values."""
    selectors: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--page" and allow_page:
            selectors.setdefault("page", []).append("true")
            index += 1
            continue
        if "=" not in token:
            raise ValueError(f"invalid artifact selector: {token}")
        key, value = token.split("=", 1)
        if key == "note":
            value = " ".join([value, *tokens[index + 1:]]).strip()
            index = len(tokens)
        else:
            index += 1
        if key not in {"artifact", "step", "pipeline", "job", "serial", "topic", "file", "dir", "name", "note"}:
            raise ValueError(f"unknown artifact selector: {key}")
        if not value:
            raise ValueError(f"artifact selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
    return selectors


def parse_search_selectors(tokens: list[str]) -> dict[str, list[str]]:
    """Parse search selectors and scope flags."""
    selectors: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SEARCH_FLAGS:
            selectors.setdefault(token.removeprefix("--"), []).append("true")
            index += 1
            continue
        if "=" not in token:
            raise ValueError(f"invalid search selector: {token}")
        key, value = token.split("=", 1)
        if key not in {"artifact", "step", "pipeline", "job", "serial", "name", "filename", "note", "content", "since", "until"}:
            raise ValueError(f"unknown search selector: {key}")
        if not value:
            raise ValueError(f"search selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
        index += 1
    return selectors


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
        store = context.artifact_store("artifact attach")
        context.audit_capability("artifact.read")
        context.audit_capability("artifact.write")
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
    store = context.artifact_store("artifact import")
    context.audit_capability("filesystem.read")
    context.audit_capability("artifact.write")
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


def pop_page_flag(selectors: dict[str, list[str]]) -> bool:
    """Remove and return the internal artifact-list page flag."""
    return bool(selectors.pop("page", []))


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
    store = context.artifact_store("artifact")
    context.audit_capability("artifact.write")
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
    store = context.artifact_store("artifact")
    context.audit_capability("filesystem.read")
    context.audit_capability("artifact.write")
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
    store = context.artifact_store("artifact")
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


def select_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> list[Artifact]:
    """Return artifacts selected by id, provenance, serial, or topic."""
    context.audit_capability("artifact.read")
    store = context.artifact_store("artifact")
    artifact_id = single_value(selectors, "artifact")
    if artifact_id is not None:
        artifacts = [store.get(artifact_id)]
        return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))
    serial = single_value(selectors, "serial")
    if serial is not None and serial.startswith("artifact-"):
        artifacts = [store.get(serial)]
        return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))
    scope = resolve_artifact_scope(context, selectors)
    artifacts = store.list(
        job_id=scope.job_id,
        pipeline_id=scope.pipeline_id,
        command_run_id=scope.command_run_id,
    )
    return filter_artifacts_by_topic(context, artifacts, selectors.get("topic", []))


def search_artifacts(context: CommandContext, selectors: dict[str, list[str]]) -> list[Artifact]:
    """Return artifacts matching search/regexp query selectors."""
    context.audit_capability("artifact.read")
    store = context.artifact_store("search")
    artifact_id = single_value(selectors, "artifact")
    if artifact_id is not None:
        artifacts = [store.get(artifact_id)]
    else:
        serial = single_value(selectors, "serial")
        if serial is not None and serial.startswith("artifact-"):
            artifacts = [store.get(serial)]
        else:
            scope = resolve_artifact_scope(context, selectors)
            artifacts = store.list(
                job_id=scope.job_id,
                pipeline_id=scope.pipeline_id,
                command_run_id=scope.command_run_id,
            )
    return filter_artifact_time_window(
        filter_artifact_search(
            artifacts,
            selectors,
            use_regexp="regexp" in selectors,
        ),
        since=single_value(selectors, "since"),
        until=single_value(selectors, "until"),
    )


def filter_artifacts_by_topic(
    context: CommandContext,
    artifacts: list[Artifact],
    topics: list[str],
) -> list[Artifact]:
    """Filter artifacts by main-DB artifact event topics."""
    if not topics:
        return artifacts
    allowed_ids = artifact_ids_for_topics(context, topics)
    return [artifact for artifact in artifacts if artifact.artifact_id in allowed_ids]


def artifact_ids_for_topics(context: CommandContext, topics: list[str]) -> set[str]:
    """Return artifact durable ids referenced by selected artifact topics."""
    ids: set[str] = set()
    events = context.event_store("artifact topic selector")
    for topic in topics:
        for event in events.events_matching(topic=topic, limit=100000):
            artifact_id = event.payload.get("artifact_id")
            if artifact_id:
                ids.add(str(artifact_id))
    return ids


def search_artifact_command(context: CommandContext, tokens: list[str]) -> None:
    """Run artifact metadata search from the namespaced artifact command."""
    selectors = parse_search_selectors(tokens)
    if not any(field in selectors for field in SEARCH_FIELDS) and "serial" not in selectors:
        raise ValueError("artifact search requires name=, filename=, note=, content=, or serial=")
    artifacts = search_artifacts(context, selectors)
    if not artifacts:
        context.output("no artifacts matched")
        return
    for artifact in artifacts:
        context.output(format_artifact_row(artifact))


def filter_artifact_search(
    artifacts: list[Artifact],
    selectors: dict[str, list[str]],
    *,
    use_regexp: bool,
) -> list[Artifact]:
    """Filter artifacts by field-specific query selectors."""
    queries = artifact_search_queries(selectors, use_regexp=use_regexp)
    return [artifact for artifact in artifacts if all(query_matches_artifact(query, artifact) for query in queries)]


def filter_artifact_serials(artifacts: list[Artifact], serials: list[str]) -> list[Artifact]:
    """Filter artifacts by exact durable serial selectors."""
    if not serials:
        return artifacts
    wanted = set(serials)
    return [artifact for artifact in artifacts if artifact_serials(artifact) & wanted]


def artifact_serials(artifact: Artifact) -> set[str]:
    """Return durable serials associated with one artifact."""
    return {
        value
        for value in {
            artifact.artifact_id,
            artifact.pipeline_id,
            artifact.command_run_id,
            str(artifact.job_id) if artifact.job_id is not None else None,
        }
        if value
    }


@dataclass(frozen=True, slots=True)
class ArtifactScope:
    """Resolved artifact provenance selectors."""

    job_id: str | None = None
    pipeline_id: str | None = None
    command_run_id: str | None = None


def resolve_artifact_scope(context: CommandContext, selectors: dict[str, list[str]]) -> ArtifactScope:
    """Resolve run/pipeline/job/serial selectors into artifact provenance scope."""
    serial = single_value(selectors, "serial")
    explicit = ArtifactScope(
        job_id=single_value(selectors, "job"),
        pipeline_id=resolve_pipeline_selector(context, single_value(selectors, "pipeline")),
        command_run_id=resolve_run_selector(context, single_value(selectors, "step")),
    )
    if serial is None:
        return explicit
    if any((explicit.job_id, explicit.pipeline_id, explicit.command_run_id)):
        raise ValueError("serial= cannot be combined with step=, pipeline=, or job=")
    # serial= is the durable selector form. It resolves to the same underlying
    # provenance columns as the shorter local IDs.
    return resolve_serial_scope(context, serial)


def resolve_serial_scope(context: CommandContext, serial: str) -> ArtifactScope:
    """Resolve a durable runtime serial to an artifact provenance scope."""
    if serial.startswith("artifact-"):
        raise ValueError("artifacts are not attached to other artifacts; use artifact= to select existing artifacts")
    if serial.startswith("pipeline-"):
        return ArtifactScope(pipeline_id=serial)
    if serial.startswith("job-"):
        job_id = resolve_job_serial(context, serial)
        if job_id is None:
            raise ValueError(f"unknown job serial: {serial}")
        return ArtifactScope(job_id=job_id)
    return ArtifactScope(command_run_id=serial)


def resolve_job_serial(context: CommandContext, serial: str) -> str | None:
    """Resolve a durable job serial to the local job id stored with artifacts."""
    return context.runtime_store("artifact").job_id_for_serial(serial)


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing step id to the durable step serial."""
    if value is None:
        return None
    return context.runtime_store("artifact").resolve_run_serial(value)


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing pipeline id to the durable pipeline serial."""
    if value is None:
        return None
    return context.runtime_store("artifact").resolve_pipeline_serial(value)


def artifact_search_queries(selectors: dict[str, list[str]], *, use_regexp: bool) -> list[tuple[str, str | re.Pattern[str]]]:
    """Compile search query selectors for artifact metadata/content fields."""
    queries: list[tuple[str, str | re.Pattern[str]]] = []
    for field in SEARCH_FIELDS:
        for value in selectors.get(field, []):
            if use_regexp:
                try:
                    queries.append((field, re.compile(value, re.IGNORECASE)))
                except re.error as exc:
                    raise ValueError(f"invalid search --regexp pattern for {field}=: {exc}") from exc
            else:
                queries.append((field, value.casefold()))
    return queries


def query_matches_artifact(query: tuple[str, str | re.Pattern[str]], artifact: Artifact) -> bool:
    """Return whether one field query matches one artifact."""
    field, expected = query
    value = artifact_field_value(artifact, field)
    if isinstance(expected, re.Pattern):
        return expected.search(value) is not None
    return expected in value.casefold()


def artifact_field_value(artifact: Artifact, field: str) -> str:
    """Return one searchable artifact field as text."""
    fields = {
        "name": artifact.name,
        "filename": Path(artifact.source_path or "").name,
        "note": artifact.note or "",
        "content": artifact_text_content(artifact),
    }
    try:
        return fields[field]
    except KeyError as exc:
        raise ValueError(f"unsupported artifact search field: {field}") from exc


def artifact_text_content(artifact: Artifact) -> str:
    """Decode artifact body for content searches."""
    return artifact.body.decode("utf-8", errors="ignore")


def filter_artifact_time_window(
    artifacts: list[Artifact],
    *,
    since: str | None,
    until: str | None,
) -> list[Artifact]:
    """Filter artifacts by created_at time window."""
    since_time = parse_compact_time(since, until=False) if since is not None else None
    until_time = parse_compact_time(until, until=True) if until is not None else None
    return [
        artifact
        for artifact in artifacts
        if artifact_in_time_window(artifact, since=since_time, until=until_time)
    ]


def artifact_in_time_window(
    artifact: Artifact,
    *,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    """Return whether artifact creation time is within an optional window."""
    created = datetime.fromisoformat(artifact.created_at).replace(tzinfo=None)
    return (since is None or created >= since) and (until is None or created <= until)


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
        f"commandlet={artifact.commandlet or ''} job={artifact.job_id or ''} "
        f"pipeline={artifact.pipeline_id or ''} step={artifact.command_run_id or ''}"
    )


def safe_artifact_filename(artifact: Artifact) -> str:
    """Build a stable export filename for a stored artifact."""
    clean = "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in artifact.name).strip("_")
    return f"{artifact.id}-{clean or artifact.artifact_id}"


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.run_aliases().values(), key=int)


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    if context.db is None:
        return []
    return sorted(context.db.pipeline_aliases().values(), key=int)


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


def serial_ids(context: CompletionContext) -> list[str]:
    """Return durable serials for completion."""
    if context.db is None:
        return []
    return context.db.serials()


def artifact_topics(context: CompletionContext) -> list[str]:
    """Return artifact event topics for selector completion."""
    if context.db is None:
        return []
    return sorted(topic for topic in context.db.topics() if topic.startswith("artifact."))


def plugins() -> tuple[Commandlet, ...]:
    """Return artifact management and search commandlets."""
    return ArtifactCommand(), SearchCommand()
