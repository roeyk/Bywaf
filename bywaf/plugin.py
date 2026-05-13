"""Plugin protocol and shared dataclasses."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .db import EventStore
from .events import Event
from .varstore import ScopedVarStore, VarStore


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
    _varstore: VarStore = field(default_factory=VarStore, repr=False)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vars(self) -> ScopedVarStore:
        """Return this commandlet's scoped variable view."""
        return ScopedVarStore(self._varstore, self.source)

    def cancelled(self) -> bool:
        """Return whether this job, pipeline, or command run was cancelled."""
        if self.db is None:
            return False
        return self.db.cancellation_requested(
            job_id=self.metadata.get("job_id"),
            pipeline_id=self.metadata.get("pipeline_id"),
            command_run_id=self.metadata.get("command_run_id"),
        )

    def raise_if_cancelled(self) -> None:
        """Raise a clear exception when a soft-cancellation request is pending."""
        if self.cancelled():
            raise RuntimeError("commandlet cancelled")

    def request(self, topic: str, payload: dict[str, Any]) -> Event | None:
        """Write a framework request event with this commandlet's run scope."""
        if self.db is None:
            return None
        return self.db.publish(
            topic,
            payload,
            self.source,
            pipeline_id=self.metadata.get("pipeline_id"),
            command_run_id=self.metadata.get("command_run_id"),
            parent_command_run_id=self.metadata.get("parent_command_run_id"),
        )

    def output(self, text: object = "", *, end: str = "\n") -> None:
        """Request normal command output from the framework console."""
        payload = {
            "text": str(text),
            "end": end,
            "source": self.source,
            "command_run_id": self.metadata.get("command_run_id"),
            "pipeline_id": self.metadata.get("pipeline_id"),
            "job_id": self.metadata.get("job_id"),
        }
        if self.request("framework.console.output.requested", payload) is None:
            print(str(text), end=end, flush=True)

    def table(self, rows: Iterable[Mapping[str, object] | Sequence[object]], columns: Sequence[str] | None = None) -> None:
        """Render a small text table through the framework output path."""
        normalized = list(rows)
        if not normalized:
            return
        if columns is None:
            first = normalized[0]
            if isinstance(first, Mapping):
                columns = tuple(str(column) for column in first.keys())
            else:
                columns = tuple(str(index) for index in range(len(first)))
        lines = format_table(normalized, columns)
        if lines:
            self.output("\n".join(lines))

    def alert(self, message: str, *, level: str = "alert", silent: bool = False) -> None:
        """Request a framework-owned console alert.

        Commandlets should not write operator alerts directly to stdout. They
        request the alert through the event database so the interpreter can
        validate, display, suppress, or route it consistently.
        """
        payload = {
            "message": message,
            "level": level,
            "silent": silent,
            "source": self.source,
            "command_run_id": self.metadata.get("command_run_id"),
            "pipeline_id": self.metadata.get("pipeline_id"),
            "job_id": self.metadata.get("job_id"),
        }
        if self.request("framework.console.alert.requested", payload) is None and not silent:
            print(f"{self.source} <{command_run_id(self)}>: {message}", flush=True)


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
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)


def format_table(rows: Sequence[Mapping[str, object] | Sequence[object]], columns: Sequence[str]) -> list[str]:
    """Return aligned text rows for small commandlet tables."""
    values: list[list[str]] = []
    for row in rows:
        if isinstance(row, Mapping):
            values.append([str(row.get(column, "")) for column in columns])
        else:
            values.append([str(row[index]) if index < len(row) else "" for index, _column in enumerate(columns)])
    widths = [
        max(len(column), *(len(row[index]) for row in values))
        for index, column in enumerate(columns)
    ]
    header = "  ".join(column.ljust(widths[index]) for index, column in enumerate(columns))
    divider = "  ".join("-" * width for width in widths)
    body = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in values]
    return [header, divider, *body]
