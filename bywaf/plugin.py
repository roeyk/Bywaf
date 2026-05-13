"""Plugin protocol and shared dataclasses."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .db import EventStore
from .events import Event
from .varstore import VarStore


@dataclass(frozen=True, slots=True)
class CompletionSpec:
    """Declarative completion behavior for an option or argument."""

    kind: str = "none"
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    """Metadata for one positional argument.

    Runtime validation still belongs to the commandlet's parser; this metadata
    is for help, introspection, and shell completion.
    """

    name: str
    description: str = ""
    required: bool = True
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class OptionSpec:
    """Metadata for one long option exposed by a commandlet."""

    name: str
    description: str
    default: str | None = None
    choices: tuple[str, ...] = ()
    completion: CompletionSpec = field(default_factory=CompletionSpec)


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Public commandlet contract consumed by help and completion."""

    name: str
    description: str
    usage: str = ""
    examples: tuple[str, ...] = ()
    options: tuple[OptionSpec, ...] = ()
    arguments: tuple[ArgumentSpec, ...] = ()
    consumes: tuple[str, ...] = ()
    emits: tuple[str, ...] = ()


@dataclass(slots=True)
class CommandContext:
    """Runtime context passed into commandlets."""

    db: EventStore | None
    source: str
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CompletionContext:
    """Lightweight context passed into optional plugin completion hooks."""

    db: EventStore | None = None
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)


class Commandlet(Protocol):
    spec: CommandSpec

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ) -> Iterable[dict[str, Any]]:
        """Execute the commandlet and yield payload dictionaries."""
        ...


def command_run_id(context: CommandContext) -> str:
    """Return the current command run ID or a stable interactive fallback."""
    return str(context.metadata.get("command_run_id") or "interactive")


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Print a standardized discovery alert unless the commandlet is silent."""
    if not silent:
        print(f"{context.source} <{command_run_id(context)}>: {message}", flush=True)
