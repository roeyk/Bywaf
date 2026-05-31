"""Artifact and tool-problem result sections."""

from __future__ import annotations

from argparse import Namespace

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.runtime.artifact.summary import format_artifact_reference
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width
from bywaf.style import styled_subject_text


def render_artifacts_section(context: CommandContext, events: list[Event], scope: Namespace | None = None) -> str:
    """Render attached artifacts as a compact result table."""
    rows = [
        (
            format_artifact_reference(context, event),
            event.payload.get("name", ""),
            event.payload.get("content_type", ""),
            event.payload.get("size", ""),
            event.payload.get("note", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("name") or ""), event.id or 0))
    ]
    table = render_table(
        ("ARTIFACT", "NAME", "TYPE", "SIZE", "NOTE"),
        rows,
        cell_subjects=("artifact", "value", "", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    command = equivalent_artifact_command(scope) if scope is not None else ""
    if command:
        command = styled_subject_text(command_context_style_getter(context), "command_line", command)
        return f"Artifacts ({len(events)})\nInspect artifacts with: {command}\n{table}"
    return f"Artifacts ({len(events)})\n{table}"


def render_tool_errors_section(context: CommandContext, events: list[Event]) -> str:
    """Render wrapper/tool problems without falling back to raw event payloads."""
    sorted_events = sorted(events, key=lambda event: event.id or 0)
    rows = [
        (
            event.payload.get("tool", event.source),
            event.payload.get("severity", "error"),
            event.payload.get("message", ""),
            compact_target(event.payload.get("target")),
            artifact_reference_from_payload(context, event),
        )
        for event in sorted_events
    ]
    table = render_table(
        ("TOOL", "SEV", "MESSAGE", "TARGET", "ARTIFACT"),
        rows,
        cell_subjects=("value", "status", "", "url", "artifact"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    commands = inspect_artifact_commands(context, sorted_events)
    if commands:
        return f"Tool problems ({len(events)})\n{table}\nInspect artifacts with: {'; '.join(commands)}"
    return f"Tool problems ({len(events)})\n{table}"


def compact_target(value: object) -> str:
    """Return a compact target string from a tool-error payload."""
    if not isinstance(value, dict):
        return str(value or "")
    return str(value.get("url") or value.get("host") or value.get("target") or "")


def artifact_reference_from_payload(context: CommandContext, event: Event) -> str:
    """Return artifact reference text when an event carries artifact metadata."""
    if event.payload.get("artifact_id") or event.payload.get("artifact_row_id"):
        return format_artifact_reference(context, event)
    return ""


def inspect_artifact_commands(context: CommandContext, events: list[Event]) -> list[str]:
    """Return styled artifact-show commands for tool-error evidence."""
    commands: list[str] = []
    style_getter = command_context_style_getter(context)
    for event in events:
        row_id = event.payload.get("artifact_row_id")
        if row_id in (None, ""):
            continue
        command = f"artifact show {row_id}"
        commands.append(styled_subject_text(style_getter, "command_line", command))
    return list(dict.fromkeys(commands))


def equivalent_artifact_command(scope: Namespace) -> str:
    """Return the artifact-list command for the current results scope."""
    selectors = [f"{key}={value}" for key, value in scope.scope.items() if key != "all"]
    return "artifact list " + " ".join(selectors) if selectors else "artifact list"
