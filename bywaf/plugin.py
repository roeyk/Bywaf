"""Plugin protocol and shared dataclasses."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .db import EventStore, Subscription
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
    capabilities: tuple[str, ...] = ()


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
        return ScopedVarStore(
            self._varstore,
            self.source,
            self.metadata.get("run_vars", {}),
        )

    @property
    def events(self) -> "ContextEvents":
        """Return the mediated event-bus API for plugin code."""
        return ContextEvents(self)

    @property
    def pipeline_id(self) -> str | None:
        """Return the current pipeline ID, if this commandlet has one."""
        value = self.metadata.get("pipeline_id")
        return str(value) if value is not None else None

    @property
    def command_run_id(self) -> str | None:
        """Return the current command-run ID, if this commandlet has one."""
        value = self.metadata.get("command_run_id")
        return str(value) if value is not None else None

    @property
    def parent_command_run_id(self) -> str | None:
        """Return the upstream command-run ID for a pipeline stage, if present."""
        value = self.metadata.get("parent_command_run_id")
        return str(value) if value is not None else None

    @property
    def job_id(self) -> int | str | None:
        """Return the active job ID, if this commandlet is job-scoped."""
        return self.metadata.get("job_id")

    @property
    def background(self) -> bool:
        """Return whether this commandlet is running as a background stage."""
        return bool(self.metadata.get("background"))

    @property
    def input_high_watermark(self) -> int:
        """Return the highest upstream event ID already consumed."""
        value = self.metadata.get("input_high_watermark", 0)
        return int(value) if value is not None else 0

    def require_db(self, label: str | None = None) -> EventStore:
        """Return the active DB or raise a consistent user-facing error."""
        if self.db is None:
            raise ValueError(f"{label or self.source} requires an active database")
        return self.db

    def require_foreground(self, label: str | None = None) -> None:
        """Raise if a foreground-only commandlet is running in the background."""
        if self.background:
            raise ValueError(f"{label or self.source} must run in the foreground")

    def cancelled(self) -> bool:
        """Return whether this job, pipeline, or command run was cancelled."""
        if self.db is None:
            return False
        return self.db.cancellation_requested(
            job_id=self.job_id,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
        )

    def raise_if_cancelled(self) -> None:
        """Raise a clear exception when a soft-cancellation request is pending."""
        if self.cancelled():
            raise RuntimeError("commandlet cancelled")

    def request(self, topic: str, payload: dict[str, Any]) -> Event | None:
        """Write a framework request event with this commandlet's run scope."""
        if self.db is None:
            return None
        event = self.db.publish(
            topic,
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        capability = framework_request_capability(topic)
        if capability is not None:
            self.audit_capability(capability, request_event_id=event.id)
        return event

    def audit_capability(self, capability: str, *, request_event_id: int | None = None) -> None:
        """Record audit-only capability usage for this commandlet run."""
        if self.db is None:
            return
        declared = capability_declared(capability, self.declared_capabilities)
        payload = {
            "commandlet": self.source,
            "capability": capability,
            "declared": declared,
            "request_event_id": request_event_id,
            "job_id": self.job_id,
        }
        self.db.publish(
            "plugin.capability.used",
            payload,
            self.source,
            pipeline_id=self.pipeline_id,
            command_run_id=self.command_run_id,
            parent_command_run_id=self.parent_command_run_id,
        )
        if not declared:
            self.db.publish(
                "plugin.capability.missing",
                payload,
                self.source,
                pipeline_id=self.pipeline_id,
                command_run_id=self.command_run_id,
                parent_command_run_id=self.parent_command_run_id,
            )

    @property
    def declared_capabilities(self) -> tuple[str, ...]:
        """Return capabilities declared or implied for this commandlet."""
        value = self.metadata.get("capabilities", ())
        return tuple(str(capability) for capability in value)

    def output(self, text: object = "", *, end: str = "\n") -> None:
        """Request normal command output from the framework console."""
        payload = {
            "text": str(text),
            "end": end,
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
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
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
        }
        if self.request("framework.console.alert.requested", payload) is None and not silent:
            print(f"{self.source} <{command_run_id(self)}>: {message}", flush=True)

    def page_file(self, path: str | Path) -> None:
        """Request framework-owned file paging for terminal and GUI frontends."""
        file_path = Path(path).expanduser()
        payload = {
            "path": str(file_path),
            "source": self.source,
            "command_run_id": self.command_run_id,
            "pipeline_id": self.pipeline_id,
            "job_id": self.job_id,
            "background": self.background,
        }
        if self.request("framework.file.page.requested", payload) is None:
            print(file_path.read_text(errors="replace"), end="", flush=True)


@dataclass(slots=True)
class CompletionContext:
    """Lightweight context passed into optional plugin completion hooks."""

    db: EventStore | None = None
    varstore: VarStore = field(default_factory=VarStore)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ContextEvents:
    """Capability-aware event API exposed to commandlets.

    This is the preferred plugin-facing abstraction over raw `EventStore`.
    It keeps event reads/writes scoped and auditable while leaving the storage
    implementation free to change behind the API.
    """

    context: CommandContext

    def publish(self, topic: str, payload: dict[str, Any]) -> Event:
        """Publish one event in the current commandlet scope."""
        db = self.context.require_db(f"{self.context.source} event publish")
        self.context.audit_capability(f"db.write:{topic}")
        return db.publish(
            topic,
            payload,
            self.context.source,
            pipeline_id=self.context.pipeline_id,
            command_run_id=self.context.command_run_id,
            parent_command_run_id=self.context.parent_command_run_id,
        )

    def fetch(
        self,
        topics: tuple[str, ...],
        *,
        after_id: int = 0,
        limit: int = 100,
        pipeline_id: str | None = None,
        command_run_id: str | None = None,
        parent_command_run_id: str | None = None,
    ) -> list[Event]:
        """Fetch events by topic with optional run/pipeline scoping."""
        db = self.context.require_db(f"{self.context.source} event fetch")
        for topic in topics:
            self.context.audit_capability(f"db.read:{topic}")
        return db.fetch(
            Subscription(
                topics=topics,
                after_id=after_id,
                limit=limit,
                pipeline_id=pipeline_id,
                command_run_id=command_run_id,
                parent_command_run_id=parent_command_run_id,
            )
        )

    def query(
        self,
        *,
        topic: str | None = None,
        run: str | None = None,
        pipeline: str | None = None,
        limit: int = 1000,
    ) -> list[Event]:
        """Query events with optional topic, run, and pipeline filters."""
        db = self.context.require_db(f"{self.context.source} event query")
        self.context.audit_capability(f"db.read:{topic}" if topic else "db.read:*")
        return db.events_matching(
            topic=topic,
            command_run_id=run,
            pipeline_id=pipeline,
            limit=limit,
        )

    def topics(self) -> list[str]:
        """Return known event topics after auditing broad DB read access."""
        db = self.context.require_db(f"{self.context.source} event topics")
        self.context.audit_capability("db.read:*")
        return db.topics()


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


class CommandletBase:
    """Convenience base class for commandlets that use argparse."""

    spec: CommandSpec

    def parser(self) -> argparse.ArgumentParser:
        """Return an argparse parser named after this commandlet."""
        return argparse.ArgumentParser(prog=self.spec.name)

    def parse_args(self, args: list[str]) -> argparse.Namespace:
        """Parse commandlet arguments with the commandlet parser."""
        return self.parser().parse_args(args)


def command_run_id(context: CommandContext) -> str:
    """Return the current command run ID or a stable interactive fallback."""
    return context.command_run_id or "interactive"


def emit_alert(context: CommandContext, message: str, *, silent: bool = False) -> None:
    """Backward-compatible wrapper around CommandContext.alert()."""
    context.alert(message, silent=silent)


def framework_request_capability(topic: str) -> str | None:
    """Map a framework request topic to the capability it uses."""
    match topic:
        case "framework.console.output.requested":
            return "framework.console.output"
        case "framework.console.alert.requested":
            return "framework.console.alert"
        case "framework.file.page.requested":
            return "framework.file.page"
        case "shell.prompt.requested":
            return "framework.prompt.change"
        case topic if topic.startswith("framework.job."):
            return "framework.job.control"
        case topic if topic.startswith("framework.pipeline."):
            return "framework.pipeline.control"
        case topic if topic.startswith("framework.") and topic.endswith(".requested"):
            return "framework.request"
        case _:
            return None


def capability_declared(capability: str, declarations: Iterable[str]) -> bool:
    """Return whether a capability is exactly declared or covered by a wildcard."""
    for declaration in declarations:
        if capability == declaration:
            return True
        if declaration.endswith(":*") and capability.startswith(declaration[:-1]):
            return True
    return False


def implied_capabilities(spec: CommandSpec) -> tuple[str, ...]:
    """Return capabilities implied by commandlet metadata."""
    capabilities = set(spec.capabilities)
    capabilities.update(f"db.read:{topic}" for topic in spec.consumes)
    capabilities.update(f"db.write:{topic}" for topic in spec.emits)
    return tuple(sorted(capabilities))


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
