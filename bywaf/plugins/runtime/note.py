"""Runtime note commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Adds operator notes to runtime entities through event records.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bywaf.event import Event
from bywaf.time_format import format_operator_timestamp
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


@commandlet(
    name="note",
    description="Show or save notes attached to jobs, pipelines, and pipeline steps.",
    usage="note [add] <step=id|pipeline=id|job=id> [text=note|file=path]",
    examples=(
        "note step=1",
        "note pipeline=1",
        "note job=12 file=notes.txt",
        "note add step=1 text=follow-up note",
    ),
)
@argument(
    "selector",
    "add, step=, pipeline=, or job= selector",
    completion=CompletionSpec("choice", ("add", "step=", "pipeline=", "job=")),
)
@argument("value", "optional text= note or file= path", required=False, completion="path")
class Note(CommandletBase):
    """Display timestamped notes recorded by framework-level `note=` selectors."""

    def database_actions_for_args(self, args: list[str]) -> tuple[str, ...]:
        """Classify note creation separately from note display/export."""
        return ("write",) if args and args[0] == "add" else ("view",)

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Show matching notes or save them to a file."""
        del input_events
        mode, selectors = parse_note_args(args)
        if mode == "add":
            add_note(context, selectors)
            return ()
        events = select_note_events(context, selectors)
        lines = [format_note_event(event) for event in events]
        if "file" in selectors:
            # Showing notes and saving notes share selection logic; file= only
            # changes the sink from console output to a project artifact path.
            path = Path(selectors["file"]).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            context.audit_capability("filesystem.write")
            path.write_text("\n".join(lines) + ("\n" if lines else ""))
            context.output(f"saved {len(lines)} notes to {path}")
        else:
            for line in lines:
                context.output(line)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete note selectors and file paths."""
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        if prefix.startswith("text="):
            return []
        if prefix.startswith("step="):
            return [f"step={value}" for value in run_ids(context)]
        if prefix.startswith("pipeline="):
            return [f"pipeline={value}" for value in pipeline_ids(context)]
        if prefix.startswith("job="):
            return [f"job={value}" for value in job_ids(context)]
        if not args:
            return ["add", "step=", "pipeline=", "job="]
        if args == ["add"]:
            return ["step=", "pipeline=", "job="]
        return ["file=", "text="] if args and args[0] == "add" else ["file="]


def parse_note_args(args: list[str]) -> tuple[str, dict[str, str]]:
    """Parse `note` command mode and selectors."""
    if args and args[0] == "add":
        return "add", parse_note_selectors(args[1:], allow_text=True)
    return "show", parse_note_selectors(args, allow_text=False)


def parse_note_selectors(args: list[str], *, allow_text: bool) -> dict[str, str]:
    """Parse `note` command selectors and optional final text."""
    selectors: dict[str, str] = {}
    index = 0
    while index < len(args):
        arg = args[index]
        if "=" not in arg:
            raise ValueError(f"invalid note selector: {arg}")
        key, value = arg.split("=", 1)
        if key == "text":
            if not allow_text:
                raise ValueError("text= is only valid with note add")
            value = " ".join([value, *args[index + 1:]]).strip()
            index = len(args)
        else:
            index += 1
        if key not in {"step", "pipeline", "job", "file", "text"}:
            raise ValueError(f"unknown note selector: {key}")
        if not value:
            raise ValueError(f"note selector {key}= requires a value")
        selectors[key] = value
    scopes = [key for key in ("step", "pipeline", "job") if key in selectors]
    if len(scopes) != 1:
        raise ValueError("note requires exactly one step=, pipeline=, or job= selector")
    if allow_text and ("text" in selectors) == ("file" in selectors):
        raise ValueError("note add requires exactly one text= or file= selector")
    return selectors


def add_note(context: CommandContext, selectors: dict[str, str]) -> None:
    """Append a note to an existing runtime entity."""
    events = context.event_store("note")
    selectors = resolve_note_selectors(context, selectors)
    note_text = selectors.get("text")
    if note_text is None:
        # file= imports operator-authored text into the audit stream; the file
        # itself is not retained unless separately attached as an artifact.
        path = Path(selectors["file"]).expanduser()
        context.audit_capability("filesystem.read")
        note_text = path.read_text(errors="replace").strip()
    payload = {
        "note": note_text,
        "job_id": int(selectors["job"]) if "job" in selectors else None,
        "pipeline_id": selectors.get("pipeline"),
        "command_run_id": selectors.get("step"),
        "parent_command_run_id": None,
        "commandlet": "note",
    }
    events.publish(
        "note.attached",
        payload,
        "framework",
        pipeline_id=selectors.get("pipeline"),
        command_run_id=selectors.get("step"),
    )
    context.output("note added")


def select_note_events(context: CommandContext, selectors: dict[str, str]) -> list[Event]:
    """Return note events matching the selected runtime entity."""
    events = context.event_store("note")
    selectors = resolve_note_selectors(context, selectors)
    if "job" in selectors:
        job_id = int(selectors["job"])
        return [event for event in events.events_for_job(job_id) if event.topic == "note.attached"]
    return events.events_matching(
        topic="note.attached",
        command_run_id=selectors.get("step"),
        pipeline_id=selectors.get("pipeline"),
    )


def format_note_event(event: Event) -> str:
    """Format one note with timestamp first."""
    timestamp = format_operator_timestamp(event.created_at)
    job_id = event.payload.get("job_id", "")
    pipeline_id = event.payload.get("pipeline_id") or event.pipeline_id or ""
    run_id = event.payload.get("command_run_id") or event.command_run_id or ""
    commandlet = event.payload.get("commandlet", event.source)
    note = event.payload.get("note", "")
    return f"{timestamp} job={job_id} pipeline={pipeline_id} step={run_id} {commandlet}: {note}"


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return sorted(runtime.run_aliases().values(), key=int)


def pipeline_ids(context: CompletionContext) -> list[str]:
    """Return pipeline IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return sorted(runtime.pipeline_aliases().values(), key=int)


def job_ids(context: CompletionContext) -> list[str]:
    """Return job IDs for completion."""
    try:
        runtime = context.runtime_store("note completion")
    except ValueError:
        return []
    return [str(row["id"]) for row in runtime.jobs()]


def resolve_note_selectors(context: CommandContext, selectors: dict[str, str]) -> dict[str, str]:
    """Resolve user-facing runtime IDs to durable serials for note events."""
    resolved = dict(selectors)
    runtime = context.runtime_store("note")
    if "step" in resolved:
        resolved["step"] = runtime.resolve_run_serial(resolved["step"])
    if "pipeline" in resolved:
        resolved["pipeline"] = runtime.resolve_pipeline_serial(resolved["pipeline"])
    if "job" in resolved:
        resolved["job"] = resolve_job_selector(context, resolved["job"])
    return resolved


def resolve_job_selector(context: CommandContext, value: str) -> str:
    """Resolve a local job id or durable job serial for note selectors."""
    if value.isdigit():
        return value
    resolved = context.runtime_store("note").job_id_for_serial(value)
    if resolved is None:
        raise ValueError(f"unknown job: {value}")
    return resolved


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Note()
