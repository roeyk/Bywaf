"""At-file argument expansion for runner commandlets.

Provides framework-level `@file`, `@lines:`, and `@raw:` expansion plus audit
and artifact provenance for files read before plugin argument parsing.

Used by:
- runner.core: expands commandlet arguments before plan handling and execution.
- tests: validate literal, text, line, and raw expansion behavior.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..events import Event
from ..plugin import CommandContext


@dataclass(frozen=True, slots=True)
class AtFileExpansion:
    """One framework-level at-file expansion applied to commandlet args."""

    token: str
    mode: Literal["text", "lines", "raw"]
    path: Path
    produced: int


def expand_at_file_args(context: CommandContext, args: list[str]) -> list[str]:
    """Expand framework-level at-file arguments before plugin parsing."""
    expanded: list[str] = []
    for arg in args:
        values, expansion = expand_at_file_arg(arg)
        expanded.extend(values)
        if expansion is not None:
            context.audit_capability("filesystem.read")
            artifact_id = attach_at_file_artifact(context, expansion)
            publish_at_file_expansion(context, expansion, artifact_id=artifact_id)
    return expanded


def expand_at_file_arg(arg: str) -> tuple[list[str], AtFileExpansion | None]:
    """Expand one `@` argument or return it unchanged."""
    if "=@" in arg and not arg.startswith("@"):
        key, value = arg.split("=", 1)
        values, expansion = expand_at_file_arg(value)
        return [f"{key}={','.join(values)}"], expansion
    if not arg.startswith("@"):
        return [arg], None
    if arg.startswith("@@"):
        return [arg[1:]], None
    mode, raw_path = parse_at_file_token(arg)
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise ValueError(f"at-file path does not exist: {path}")
    if path.is_dir():
        raise ValueError(f"at-file path is a directory: {path}")
    text = path.read_text(errors="replace")
    values = at_file_expanders()[mode](text)
    return values, AtFileExpansion(arg, mode, path, len(values))


def parse_at_file_token(arg: str) -> tuple[Literal["text", "lines", "raw"], str]:
    """Return expansion mode and path for one at-file token."""
    if arg.startswith("@lines:"):
        return "lines", arg.removeprefix("@lines:")
    if arg.startswith("@raw:"):
        return "raw", arg.removeprefix("@raw:")
    return "text", arg.removeprefix("@")


def at_file_expanders() -> dict[str, Callable[[str], list[str]]]:
    """Return at-file content expanders keyed by expansion mode."""
    return {
        "lines": lambda text: [line.strip() for line in text.splitlines() if line.strip()],
        "raw": lambda text: [text],
        "text": lambda text: [text],
    }


def attach_at_file_artifact(context: CommandContext, expansion: AtFileExpansion) -> str | None:
    """Attach an expanded input file as provenance when artifact storage works."""
    try:
        artifact = context.artifacts.attach_file(
            expansion.path,
            name=expansion.path.name,
            note=f"framework argument expansion {expansion.mode} from {expansion.token}",
        )
    except (RuntimeError, ValueError):
        return None
    return artifact.artifact_id


def publish_at_file_expansion(
    context: CommandContext,
    expansion: AtFileExpansion,
    *,
    artifact_id: str | None = None,
) -> Event | None:
    """Record one framework-owned at-file expansion."""
    if context._db is None:
        return None
    payload = {
        "operator": "@",
        "token": expansion.token,
        "mode": expansion.mode,
        "path": str(expansion.path),
        "produced": expansion.produced,
        "job_id": context.job_id,
        "pipeline_id": context.pipeline_id,
        "command_run_id": context.command_run_id,
        "commandlet": context.source,
    }
    if artifact_id is not None:
        payload["artifact_id"] = artifact_id
    return context._db.publish(
        "framework.argument.expanded",
        payload,
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )
