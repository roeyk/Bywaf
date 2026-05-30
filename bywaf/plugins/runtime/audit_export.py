"""Audit export writers.

Writes selected audit events to JSON, JSONL, SQLite, or compact PDF outputs,
including optional encryption for supported formats.

Used by:
- runtime.audit: implement `audit export`."""

from __future__ import annotations

import getpass
import importlib
import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from bywaf.db import export_encrypted_database
from bywaf.event import Event
from bywaf.plugin import CommandContext

from .audit_selectors import selected_events


def export_events(
    context: CommandContext,
    path: Path,
    selectors: dict[str, str],
    requested_format: str,
    limit: int,
    *,
    encrypt: bool = False,
) -> None:
    """Export selected audit events to JSON, JSONL, PDF, or SQLite."""
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
