"""Audit log inspection and export commandlet."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import getpass
import importlib
from collections.abc import Iterable
from datetime import datetime, time
from pathlib import Path

from bywaf.db import export_encrypted_database
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
AUDIT_FORMATS = ("json", "jsonl", "pdf", "sqlite")
AUDIT_SELECTORS = {"file", "topic", "run", "pipeline", "job", "since", "until"}


@commandlet(
    name="audit",
    description="Show or export the SQLite-backed audit log.",
    usage="audit <show|export> [file=<path>] [topic=<topic>|run=<id>|pipeline=<id>|job=<id>]",
    examples=(
        "audit show topic=plugin.capability.used",
        "audit show run=hostscanner-...",
        "audit show since=20260517 until=20260518",
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
        parser.add_argument("--encrypt", action="store_true")
        parser.add_argument("--limit", type=int, default=1000)
        parsed = parser.parse_args(args)
        selectors = parse_selectors(parsed.selectors)
        match parsed.action:
            case "show":
                for event in selected_events(context, selectors, parsed.limit):
                    context.output(json.dumps(event_record(event), sort_keys=True))
            case "export":
                path = require_selector(selectors, "file")
                export_events(
                    context,
                    Path(path).expanduser(),
                    selectors,
                    parsed.format,
                    parsed.limit,
                    encrypt=parsed.encrypt,
                )
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
        return ["file=", "topic=", "run=", "pipeline=", "job=", "since=", "until="]


def parse_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse key=value selector tokens into a dictionary."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ValueError(f"invalid audit selector: {token}")
        key, value = token.split("=", 1)
        if key not in AUDIT_SELECTORS:
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
        events = db.events_for_job(int(selectors["job"]), limit=100000)
    else:
        events = db.events_matching(
            topic=selectors.get("topic"),
            command_run_id=selectors.get("run"),
            pipeline_id=selectors.get("pipeline"),
            limit=100000,
        )
    window = audit_window(context, selectors)
    return [event for event in events if event_in_window(event, window)][:limit]


def audit_window(
    context: CommandContext,
    selectors: dict[str, str],
) -> tuple[int | None, int | None, datetime | None, datetime | None]:
    """Resolve since/until selectors to event-id or timestamp bounds."""
    since_id, since_time = resolve_bound(context, selectors.get("since"), since=True)
    until_id, until_time = resolve_bound(context, selectors.get("until"), since=False)
    return since_id, until_id, since_time, until_time


def resolve_bound(
    context: CommandContext,
    value: str | None,
    *,
    since: bool,
) -> tuple[int | None, datetime | None]:
    """Resolve one audit time-window bound."""
    if value is None:
        return None, None
    kind, raw = split_bound(value)
    match kind:
        case "time":
            return None, parse_compact_time(raw, until=not since)
        case "run":
            return entity_event_id(context, command_run_id=raw, first=since), None
        case "pipeline":
            return entity_event_id(context, pipeline_id=raw, first=since), None
        case "job":
            events = context.require_db("audit").events_for_job(int(raw), limit=100000)
            if not events:
                raise ValueError(f"unknown audit job bound: {raw}")
            event_id = events[0].id if since else events[-1].id
            return event_id, None
        case _:
            raise ValueError(f"unsupported audit bound type: {kind}")


def split_bound(value: str) -> tuple[str, str]:
    """Split `kind:value`, defaulting unqualified values to `time`."""
    if ":" not in value:
        return "time", value
    kind, raw = value.split(":", 1)
    if not raw:
        raise ValueError(f"audit {kind}: bound requires a value")
    return kind, raw


def parse_compact_time(value: str, *, until: bool) -> datetime:
    """Parse yyyymmdd[HH[MM[SS]]] into a datetime bound."""
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) not in {8, 10, 12, 14}:
        raise ValueError("audit time must be yyyymmdd[HH[MM[SS]]]")
    year = int(digits[:4])
    month = int(digits[4:6])
    day = int(digits[6:8])
    hour = int(digits[8:10]) if len(digits) >= 10 else (23 if until else 0)
    minute = int(digits[10:12]) if len(digits) >= 12 else (59 if until else 0)
    second = int(digits[12:14]) if len(digits) >= 14 else (59 if until else 0)
    return datetime.combine(datetime(year, month, day).date(), time(hour, minute, second))


def entity_event_id(
    context: CommandContext,
    *,
    command_run_id: str | None = None,
    pipeline_id: str | None = None,
    first: bool,
) -> int:
    """Return the first or last event ID for a run or pipeline bound."""
    events = context.require_db("audit").events_matching(
        command_run_id=command_run_id,
        pipeline_id=pipeline_id,
        limit=100000,
    )
    label = f"run {command_run_id}" if command_run_id else f"pipeline {pipeline_id}"
    if not events:
        raise ValueError(f"unknown audit bound: {label}")
    event_id = events[0].id if first else events[-1].id
    if event_id is None:
        raise ValueError(f"audit bound has no event id: {label}")
    return event_id


def event_in_window(
    event: Event,
    window: tuple[int | None, int | None, datetime | None, datetime | None],
) -> bool:
    """Return whether an event falls within resolved audit bounds."""
    since_id, until_id, since_time, until_time = window
    event_id = event.id or 0
    created = event.created_at.replace(tzinfo=None)
    return (
        (since_id is None or event_id >= since_id)
        and (until_id is None or event_id <= until_id)
        and (since_time is None or created >= since_time)
        and (until_time is None or created <= until_time)
    )


def export_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    requested_format: str,
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export selected audit events to JSON, JSONL, or SQLite."""
    db = context.require_db("audit")
    export_format = choose_format(path, requested_format)
    path.parent.mkdir(parents=True, exist_ok=True)
    match export_format:
        case "sqlite":
            db.checkpoint()
            if encrypt:
                passphrase = prompt_export_passphrase(path)
                export_encrypted_database(
                    db.path,
                    path,
                    passphrase,
                    source_passphrase=db.passphrase,
                )
            else:
                shutil.copy2(db.path, path)
        case "json":
            reject_unsupported_encryption(encrypt, export_format)
            records = [event_record(event) for event in selected_events(context, selectors, limit)]
            path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
        case "jsonl":
            reject_unsupported_encryption(encrypt, export_format)
            with path.open("w") as handle:
                for event in selected_events(context, selectors, limit):
                    handle.write(json.dumps(event_record(event), sort_keys=True) + "\n")
        case "pdf":
            records = [event_record(event) for event in selected_events(context, selectors, limit)]
            if encrypt:
                write_encrypted_pdf(path, records)
            else:
                write_pdf(path, records)
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
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".json":
        return "json"
    return "jsonl"


def prompt_export_passphrase(path: Path) -> str:
    """Prompt twice for an export encryption passphrase."""
    first = getpass.getpass(f"Passphrase for encrypted audit export {path}: ")
    second = getpass.getpass("Confirm passphrase: ")
    if first != second:
        raise ValueError("passphrases do not match")
    if not first:
        raise ValueError("passphrase cannot be empty")
    return first


def reject_unsupported_encryption(encrypt: bool, export_format: str) -> None:
    """Reject encryption for formats without an implemented safe container."""
    if encrypt:
        raise ValueError(f"audit --encrypt is not supported for {export_format} export")


def write_encrypted_pdf(path: Path, records: list[dict[str, object]]) -> None:
    """Write a password-protected PDF using pikepdf or qpdf when available."""
    try:
        pikepdf = importlib.import_module("pikepdf")
    except ImportError:
        pikepdf = None
    if pikepdf is None and shutil.which("qpdf") is None:
        raise ValueError("encrypted PDF export requires pikepdf or qpdf")
    passphrase = prompt_export_passphrase(path)
    with tempfile.TemporaryDirectory() as tmp:
        plain = Path(tmp, "audit.pdf")
        write_pdf(plain, records)
        if pikepdf is not None:
            with pikepdf.Pdf.open(plain) as pdf:
                pdf.save(
                    path,
                    encryption=pikepdf.Encryption(
                        owner=passphrase,
                        user=passphrase,
                        R=6,
                    ),
            )
            return
        subprocess.run(
            [
                "qpdf",
                "--encrypt",
                passphrase,
                passphrase,
                "256",
                "--",
                str(plain),
                str(path),
            ],
            check=True,
        )


def write_pdf(path: Path, records: list[dict[str, object]]) -> None:
    """Write a small text-only PDF without external Python dependencies."""
    lines = ["Bywaf audit export", ""]
    lines.extend(json.dumps(record, sort_keys=True) for record in records)
    content_lines = ["BT", "/F1 9 Tf", "50 760 Td", "12 TL"]
    for line in lines[:58]:
        content_lines.append(f"({pdf_escape(line[:120])}) Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    body = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body.extend(f"{index} 0 obj\n".encode())
        body.extend(obj)
        body.extend(b"\nendobj\n")
    xref = len(body)
    body.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        body.extend(f"{offset:010d} 00000 n \n".encode())
    body.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    path.write_bytes(bytes(body))


def pdf_escape(value: str) -> str:
    """Escape text for a PDF literal string."""
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


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
