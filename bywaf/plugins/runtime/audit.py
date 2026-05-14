"""Audit log inspection and export commandlet."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterable
from pathlib import Path

from bywaf.events import Event
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

AUDIT_ACTIONS = ("export", "show")
AUDIT_FORMATS = ("json", "jsonl", "sqlite")


@commandlet(
    name="audit",
    description="Show or export the SQLite-backed audit log.",
    usage="audit <show|export> [file=<path>] [topic=<topic>|run=<id>|pipeline=<id>|job=<id>]",
    examples=(
        "audit show topic=plugin.capability.used",
        "audit show run=hostscanner-...",
        "audit export file=audit.jsonl",
        "audit export file=audit.sqlite3 --format sqlite",
    ),
    capabilities=("db.raw", "filesystem.write", "framework.console.output"),
)
@option("format", "export format", "auto", choices=("auto", *AUDIT_FORMATS))
@option("limit", "maximum events to show or export", "1000")
@argument("action", "audit operation", completion=CompletionSpec("choice", AUDIT_ACTIONS))
@argument("selector", "file=, topic=, run=, pipeline=, or job= selector", required=False)
class Audit(CommandletBase):
    """Provide first-class access to Bywaf's event audit trail."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Parse and execute one audit operation."""
        parser = self.parser()
        parser.add_argument("action", choices=AUDIT_ACTIONS)
        parser.add_argument("selectors", nargs="*")
        parser.add_argument("--format", default="auto", choices=("auto", *AUDIT_FORMATS))
        parser.add_argument("--limit", type=int, default=1000)
        parsed = parser.parse_args(args)
        selectors = parse_selectors(parsed.selectors)
        match parsed.action:
            case "show":
                for event in selected_events(context, selectors, parsed.limit):
                    context.output(json.dumps(event_record(event), sort_keys=True))
            case "export":
                path = require_selector(selectors, "file")
                export_events(context, Path(path).expanduser(), selectors, parsed.format, parsed.limit)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete audit actions, selectors, and filesystem export paths."""
        del context
        if not args:
            return list(AUDIT_ACTIONS)
        if len(args) == 1 and args[0] not in AUDIT_ACTIONS:
            return list(AUDIT_ACTIONS)
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        return ["file=", "topic=", "run=", "pipeline=", "job="]


def parse_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse key=value selector tokens into a dictionary."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError(f"invalid audit selector: {token}")
        key, value = token.split("=", 1)
        if key not in {"file", "topic", "run", "pipeline", "job"}:
            raise ValueError(f"unknown audit selector: {key}")
        if not value:
            raise ValueError(f"audit selector {key}= requires a value")
        selectors[key] = value
    return selectors


def require_selector(selectors: dict[str, str], name: str) -> str:
    """Return a required selector value or raise a user-facing error."""
    try:
        return selectors[name]
    except KeyError as exc:
        raise ValueError(f"audit {name}= is required") from exc


def selected_events(context: CommandContext, selectors: dict[str, str], limit: int) -> list[Event]:
    """Fetch events matching audit selectors."""
    db = context.require_db("audit")
    if "job" in selectors:
        return db.events_for_job(int(selectors["job"]), limit=limit)
    return db.events_matching(
        topic=selectors.get("topic"),
        command_run_id=selectors.get("run"),
        pipeline_id=selectors.get("pipeline"),
        limit=limit,
    )


def export_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    requested_format: str,
    limit: int,
) -> None:
    """Export selected audit events to JSON, JSONL, or SQLite."""
    db = context.require_db("audit")
    export_format = choose_format(path, requested_format)
    path.parent.mkdir(parents=True, exist_ok=True)
    match export_format:
        case "sqlite":
            db.checkpoint()
            shutil.copy2(db.path, path)
        case "json":
            records = [event_record(event) for event in selected_events(context, selectors, limit)]
            path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
        case "jsonl":
            with path.open("w") as handle:
                for event in selected_events(context, selectors, limit):
                    handle.write(json.dumps(event_record(event), sort_keys=True) + "\n")
        case _:
            raise ValueError(f"unsupported audit export format: {export_format}")
    context.output(f"exported audit {export_format} to {path}")


def choose_format(path: Path, requested_format: str) -> str:
    """Choose an audit export format from --format or the file suffix."""
    if requested_format != "auto":
        return requested_format
    suffix = path.suffix.lower()
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return "sqlite"
    if suffix == ".json":
        return "json"
    return "jsonl"


def event_record(event: Event) -> dict[str, object]:
    """Convert an event to a JSON-serializable audit record."""
    return {
        "id": event.id,
        "topic": event.topic,
        "payload": event.payload,
        "source": event.source,
        "created_at": event.created_at.isoformat(),
        "pipeline_id": event.pipeline_id,
        "command_run_id": event.command_run_id,
        "parent_command_run_id": event.parent_command_run_id,
    }


def complete_path(prefix: str) -> list[str]:
    """Return simple filesystem completions for audit export paths."""
    raw = Path(prefix or ".").expanduser()
    directory = raw if raw.is_dir() else raw.parent
    stem = "" if raw.is_dir() else raw.name
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []
    results: list[str] = []
    for entry in entries:
        if entry.name.startswith(stem):
            suffix = "/" if entry.is_dir() else ""
            results.append(str(entry) + suffix)
    return results


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Audit()
