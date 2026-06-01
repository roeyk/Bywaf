"""Artifact body preview rendering.

Used by:
- runtime.artifact.actions: implement `artifact cat` without mixing preview
  formatting into mutation/listing actions."""

from __future__ import annotations

import string
from pathlib import Path

from bywaf.artifacts import Artifact

from .selectors import single_value


def artifact_cat_limit(selectors: dict[str, list[str]]) -> int:
    """Return the artifact preview byte limit."""
    raw = single_value(selectors, "limit")
    if raw is None:
        return 8192
    try:
        limit = int(raw)
    except ValueError as exc:
        raise ValueError("artifact cat limit= must be an integer byte count") from exc
    if limit <= 0:
        raise ValueError("artifact cat limit= must be greater than zero")
    return min(limit, 1024 * 1024)


def format_artifact_preview(artifact: Artifact, *, limit: int, encoding: str) -> str:
    """Return a bounded body preview for one artifact."""
    shown = artifact.body[:limit]
    header = [
        f"Artifact: {artifact.id} {artifact.name} {artifact.content_type} size={artifact.size} sha256={artifact.sha256}",
    ]
    if artifact_body_is_binary(shown, artifact.content_type):
        header.append(f"Preview: binary hex, first {len(shown)} of {artifact.size} bytes")
        body_text = hex_dump(shown)
    else:
        try:
            body_text = shown.decode(encoding)
        except LookupError as exc:
            raise ValueError(f"unknown artifact cat encoding: {encoding}") from exc
        except UnicodeDecodeError:
            header.append(f"Preview: binary hex, first {len(shown)} of {artifact.size} bytes")
            body_text = hex_dump(shown)
        else:
            header.append(f"Preview: text {encoding}, first {len(shown)} of {artifact.size} bytes")
    suffix = ""
    if artifact.size > len(shown):
        suffix = f"\n[truncated after {len(shown)} of {artifact.size} bytes; use limit={artifact.size} to show all]"
    return "\n".join(header) + "\n\n" + body_text + suffix


def artifact_body_is_binary(data: bytes, content_type: str) -> bool:
    """Return whether body bytes should be previewed as binary."""
    if b"\x00" in data:
        return True
    if content_type.startswith("text/"):
        return False
    if any(marker in content_type for marker in ("json", "xml", "yaml", "javascript", "html")):
        return False
    if not data:
        return False
    control = sum(1 for value in data if value < 32 and value not in {9, 10, 13})
    return control / len(data) > 0.10


def hex_dump(data: bytes, *, width: int = 16) -> str:
    """Return a compact hex dump with offsets and ASCII gutters."""
    printable = set(bytes(string.printable, "ascii")) - {11, 12}
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{value:02x}" for value in chunk)
        gutter = "".join(chr(value) if value in printable and value >= 32 else "." for value in chunk)
        lines.append(f"{offset:08x}  {hex_bytes:<{width * 3 - 1}}  |{gutter}|")
    return "\n".join(lines)


def artifact_preview_suffix(artifact: Artifact) -> str:
    """Return the temporary suffix used when paging an artifact preview."""
    if artifact.content_type.startswith("text/"):
        return Path(artifact.name).suffix or ".txt"
    return ".hex"


def pop_selector_flag(selectors: dict[str, list[str]], name: str) -> bool:
    """Remove and return one boolean selector flag."""
    return bool(selectors.pop(name, []))
