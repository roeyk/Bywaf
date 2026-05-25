"""Runtime audit commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Displays audit events and exports audit data for inspection.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import getpass
import importlib
from argparse import Namespace
from collections.abc import Callable, Iterable
from datetime import datetime, time
from pathlib import Path

from bywaf.db import export_encrypted_database
from bywaf.events import Event
from bywaf.plugin.capabilities import implied_capabilities
from bywaf.time_format import format_operator_timestamp
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
from bywaf.registry import PluginRegistry

AUDIT_ACTIONS = ("export", "list", "show")
AUDIT_LIST_TARGETS = ("capabilities",)
AUDIT_FORMATS = ("json", "jsonl", "pdf", "sqlite")
AUDIT_SELECTORS = {"file", "topic", "step", "pipeline", "job", "serial", "since", "until"}
AUDIT_LIST_SELECTORS = {"plugin"}
AuditActionHandler = Callable[[CommandContext, Namespace, dict[str, str]], None]


@commandlet(
    name="audit",
    description="Show or export the SQLite-backed audit log.",
    usage="audit <show|export> [file=<path>] [topic=<topic>|step=<id>|pipeline=<id>|job=<id>|serial=<id>]",
    examples=(
        "audit list capabilities",
        "audit list capabilities plugin=nikto",
        "audit show topic=plugin.capability.used",
        "audit show step=1",
        "audit show serial=hostscanner-...",
        "audit show since=20260517 until=20260518",
        "audit export file=audit.jsonl",
        "audit export file=audit.sqlite3 --format sqlite",
    ),
    capabilities=("db.raw", "filesystem.write", "framework.console.output"),
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
        """Complete audit actions, selectors, and filesystem export paths."""
        del context
        if not args:
            return list(AUDIT_ACTIONS)
        if len(args) == 1 and args[0] not in AUDIT_ACTIONS:
            return list(AUDIT_ACTIONS)
        if args and args[0] == "list":
            if len(args) == 1:
                return list(AUDIT_LIST_TARGETS)
            return ["plugin="]
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
    if target != "capabilities":
        raise ValueError("audit list supports: capabilities")
    rows = capability_inventory_rows(context, plugin_filter=selectors.get("plugin"))
    context.output(format_capability_inventory(rows))


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


def parse_list_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse `audit list <target> [key=value]` selectors."""
    if not tokens:
        raise ValueError("audit list requires a target")
    target, *rest = tokens
    if target not in AUDIT_LIST_TARGETS:
        raise ValueError(f"unknown audit list target: {target}")
    selectors = {"_target": target}
    for token in rest:
        if "=" not in token:
            raise ValueError(f"invalid audit list selector: {token}")
        key, value = token.split("=", 1)
        if key not in AUDIT_LIST_SELECTORS:
            raise ValueError(f"unknown audit list selector: {key}")
        if not value:
            raise ValueError(f"audit list selector {key}= requires a value")
        selectors[key] = value
    return selectors


def capability_inventory_rows(context: CommandContext, *, plugin_filter: str | None = None) -> list[dict[str, str]]:
    """Return declaration/runtime inventory rows for framework capabilities."""
    runner = context.metadata.get("runner")
    registry = runner.registry if runner is not None else PluginRegistry.discover()
    # Compare manifest/spec declarations with actual capability audit events.
    # This gives operators a quick view of drift between what plugins claimed
    # and what they attempted during execution.
    declared = declared_capabilities(registry, plugin_filter=plugin_filter)
    used = capability_events(context, "plugin.capability.used", plugin_filter=plugin_filter)
    missing = capability_events(context, "plugin.capability.missing", plugin_filter=plugin_filter)
    names = sorted(set(declared) | set(used) | set(missing))
    return [capability_inventory_row(name, declared, used, missing) for name in names]


def declared_capabilities(registry: PluginRegistry, *, plugin_filter: str | None = None) -> dict[str, list[str]]:
    """Return declared capability names mapped to declaring commandlets."""
    declarations: dict[str, list[str]] = {}
    plugins = registry.plugins
    if plugin_filter is not None:
        if plugin_filter not in plugins:
            raise ValueError(f"unknown plugin for capability inventory: {plugin_filter}")
        plugins = {plugin_filter: plugins[plugin_filter]}
    for name, plugin in plugins.items():
        for capability in implied_capabilities(plugin.spec):
            declarations.setdefault(capability, []).append(name)
    return {capability: sorted(names) for capability, names in declarations.items()}


def capability_events(
    context: CommandContext,
    topic: str,
    *,
    plugin_filter: str | None = None,
) -> dict[str, list[Event]]:
    """Return capability audit events grouped by capability."""
    grouped: dict[str, list[Event]] = {}
    for event in context.event_store("audit").events_for_topic(topic, limit=100000):
        commandlet = str(event.payload.get("commandlet") or event.source)
        if plugin_filter is not None and commandlet != plugin_filter:
            continue
        capability = event.payload.get("capability")
        if not isinstance(capability, str) or not capability:
            continue
        grouped.setdefault(capability, []).append(event)
    return grouped


def capability_inventory_row(
    capability: str,
    declared: dict[str, list[str]],
    used: dict[str, list[Event]],
    missing: dict[str, list[Event]],
) -> dict[str, str]:
    """Build one printable capability inventory row."""
    used_events = used.get(capability, [])
    missing_events = missing.get(capability, [])
    last_event = used_events[-1] if used_events else None
    status = capability_status(capability, declared, used_events, missing_events)
    return {
        "Capability": capability,
        "Range": capability_range(capability),
        "Declared By": ", ".join(declared.get(capability, ())) or "-",
        "Last Used": format_event_time(last_event) if last_event is not None else "never",
        "Last User": str(last_event.payload.get("commandlet") or last_event.source) if last_event is not None else "-",
        "Missing": str(len(missing_events)),
        "Status": status,
    }


def capability_status(
    capability: str,
    declared: dict[str, list[str]],
    used_events: list[Event],
    missing_events: list[Event],
) -> str:
    """Return a compact status label for one capability."""
    if missing_events and capability not in declared:
        return "missing"
    if capability.endswith(":*"):
        return "broad"
    if used_events:
        return "observed"
    if capability in declared:
        return "declared-only"
    return "unknown"


def capability_range(capability: str) -> str:
    """Return the accepted capability-code family range for a capability."""
    if capability.startswith("db.read:") or capability.startswith("db.write:"):
        return "C100-C199"
    if capability.startswith("db.") or capability.startswith("artifact."):
        return "C200-C299"
    if capability.startswith("process.") or capability.startswith("filesystem."):
        return "C300-C399"
    if capability.startswith("network."):
        return "C400-C499"
    if capability.startswith("framework.secret"):
        return "C500-C599"
    if capability.startswith("framework.job") or capability.startswith("framework.pipeline"):
        return "C600-C699"
    if capability.startswith("framework.render"):
        return "C700-C799"
    if capability.startswith("plugin.") or capability.startswith("framework."):
        return "C001-C099"
    return "C900-C999"


def format_event_time(event: Event) -> str:
    """Return a user-facing timestamp with timezone."""
    return format_operator_timestamp(event.created_at)


def format_capability_inventory(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width capability inventory table."""
    columns = ["Capability", "Range", "Declared By", "Last Used", "Last User", "Missing", "Status"]
    widths = {
        column: max(len(column), *(len(row[column]) for row in rows)) if rows else len(column)
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    ruler = "  ".join("-" * widths[column] for column in columns)
    body = ["  ".join(row[column].ljust(widths[column]) for column in columns) for row in rows]
    return "\n".join([header, ruler, *body])


def require_selector(selectors: dict[str, str], name: str) -> str:
    """Return a required selector value or raise a user-facing error."""
    try:
        return selectors[name]
    except KeyError as exc:
        raise ValueError(f"audit {name}= is required") from exc


def selected_events(context: CommandContext, selectors: dict[str, str], limit: int) -> list[Event]:
    """Fetch events matching audit selectors."""
    events_store = context.event_store("audit")
    # serial= and job= require helper lookups because they may span several
    # event columns. Direct topic/step/pipeline selection can use the generic
    # event query path.
    if "serial" in selectors:
        events = events_store.events_for_serial(selectors["serial"], limit=100000)
    elif "job" in selectors:
        events = events_store.events_for_job(int(selectors["job"]), limit=100000)
    else:
        events = events_store.events_matching(
            topic=selectors.get("topic"),
            command_run_id=resolve_run_selector(context, selectors.get("step")),
            pipeline_id=resolve_pipeline_selector(context, selectors.get("pipeline")),
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
    # Bounds can be wall-clock timestamps or runtime-relative anchors such as
    # since=step:3. Resolve both to either event IDs or datetimes, then apply one
    # common event_in_window predicate.
    resolver = audit_bound_resolvers().get(kind)
    if resolver is None:
        raise ValueError(f"unsupported audit bound type: {kind}")
    return resolver(context, raw, since=since)


AuditBoundResolver = Callable[..., tuple[int | None, datetime | None]]


def audit_bound_resolvers() -> dict[str, AuditBoundResolver]:
    """Return audit since/until bound resolvers keyed by selector type."""
    return {
        "job": resolve_job_bound,
        "pipeline": resolve_pipeline_bound,
        "step": resolve_run_bound,
        "time": resolve_time_bound,
    }


def resolve_time_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a compact timestamp audit bound."""
    del context
    return None, parse_compact_time(raw, until=not since)


def resolve_run_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a step-relative audit bound."""
    return entity_event_id(
        context,
        command_run_id=context.runtime_store("audit").resolve_run_serial(raw),
        first=since,
    ), None


def resolve_pipeline_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a pipeline-relative audit bound."""
    return entity_event_id(
        context,
        pipeline_id=context.runtime_store("audit").resolve_pipeline_serial(raw),
        first=since,
    ), None


def resolve_job_bound(context: CommandContext, raw: str, *, since: bool) -> tuple[int | None, datetime | None]:
    """Resolve a job-relative audit bound."""
    events = context.event_store("audit").events_for_job(int(raw), limit=100000)
    if not events:
        raise ValueError(f"unknown audit job bound: {raw}")
    return (events[0].id if since else events[-1].id), None


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
    events = context.event_store("audit").events_matching(
        command_run_id=command_run_id,
        pipeline_id=pipeline_id,
        limit=100000,
    )
    label = f"step {command_run_id}" if command_run_id else f"pipeline {pipeline_id}"
    if not events:
        raise ValueError(f"unknown audit bound: {label}")
    event_id = events[0].id if first else events[-1].id
    if event_id is None:
        raise ValueError(f"audit bound has no event id: {label}")
    return event_id


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing step id to a durable step serial."""
    if value is None:
        return None
    return context.runtime_store("audit").resolve_run_serial(value)


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing pipeline id to a durable pipeline serial."""
    if value is None:
        return None
    return context.runtime_store("audit").resolve_pipeline_serial(value)


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
    export_format = choose_format(path, requested_format)
    path.parent.mkdir(parents=True, exist_ok=True)
    # The command surface is `audit export file=...`; suffix-based format
    # selection keeps the common path short while still allowing --format.
    handler = audit_export_handlers().get(export_format)
    if handler is None:
        raise ValueError(f"unsupported audit export format: {export_format}")
    handler(context, path, selectors, limit, encrypt=encrypt)
    context.output(f"exported audit {export_format} to {path}")


AuditExportHandler = Callable[..., None]


def audit_export_handlers() -> dict[str, AuditExportHandler]:
    """Return audit export handlers keyed by normalized format name."""
    return {
        "json": export_json_events,
        "jsonl": export_jsonl_events,
        "pdf": export_pdf_events,
        "sqlite": export_sqlite_events,
    }


def export_sqlite_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export the active audit DB as a SQLite or SQLCipher database."""
    del selectors, limit
    maintenance = context.maintenance_store("audit export")
    maintenance.checkpoint()
    if encrypt:
        passphrase = prompt_export_passphrase(path)
        export_encrypted_database(
            maintenance.path,
            path,
            passphrase,
            source_passphrase=maintenance.passphrase,
        )
    else:
        shutil.copy2(maintenance.path, path)


def export_json_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export selected audit events as JSON."""
    reject_unsupported_encryption(encrypt, "json")
    records = [event_record(event) for event in selected_events(context, selectors, limit)]
    path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")


def export_jsonl_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export selected audit events as line-delimited JSON."""
    reject_unsupported_encryption(encrypt, "jsonl")
    with path.open("w") as handle:
        for event in selected_events(context, selectors, limit):
            handle.write(json.dumps(event_record(event), sort_keys=True) + "\n")


def export_pdf_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export selected audit events as a compact PDF."""
    records = [event_record(event) for event in selected_events(context, selectors, limit)]
    if encrypt:
        write_encrypted_pdf(path, records)
    else:
        write_pdf(path, records)


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
