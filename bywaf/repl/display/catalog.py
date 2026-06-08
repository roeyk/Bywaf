"""Provider, commandlet, trigger, and topic display helpers.

Provides compact catalog views for loaded providers, commandlets, trigger rules,
and event topics.

Used by:
- repl.commands: implement `plugins`, `cmds`, `triggers`, and `topics`."""

from __future__ import annotations

from .catalog_graph import print_plugin_graph
from ...pager import page_text
from ...rendering import Column, Table, render_console_table
from ...runner import Runner

__all__ = [
    "page_generated_text",
    "print_commandlets",
    "print_plugin_graph",
    "print_plugins",
    "print_topics",
    "print_triggers",
    "render_commandlets",
]


def print_topics(runner: Runner, prefix: str = "") -> None:
    """Print event topics known to the active database, optionally filtered."""
    matched = [topic for topic in runner.events.topics() if topic.startswith(prefix)]
    for topic in matched:
        print(topic)
    if prefix and not matched:
        print(f"no matching topics: {prefix}")


def print_plugins(runner: Runner) -> None:
    """Print loaded plugin providers with compact purpose summaries."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        rows.append(
            {
                "provider": provider,
                "count": str(len(commandlets)),
                "description": provider_description(provider, commandlets, runner),
            }
        )
    if rows:
        print(
            render_console_table(
                Table(
                    (
                        Column("provider", "PLUGIN"),
                        Column("count", "CMDS"),
                        Column("description", "WHAT IT DOES"),
                    ),
                    tuple(rows),
                ),
                runner.registry.varstore.get,
            )
        )


def provider_description(provider: str, commandlets: list[str], runner: Runner) -> str:
    """Return a compact readable provider description."""
    override = provider_descriptions().get(provider)
    if override is not None:
        return override
    if len(commandlets) == 1:
        return runner.registry.plugins[commandlets[0]].spec.description
    return f"{len(commandlets)} commandlets; run `cmds` for command-level details."


def provider_descriptions() -> dict[str, str]:
    """Return concise descriptions for bundled provider groups."""
    return {
        "analysis": "Finding normalization, reporting, and file-analysis helpers.",
        "discovery": "Host and target discovery commandlets.",
        "http": "HTTP probing, fingerprinting, screenshot, and Nikto wrappers.",
        "identity": "Identity and directory-service probes.",
        "network": "Network service discovery and protocol probes.",
        "os": "Local filesystem inspection helpers.",
        "recon": "External and DNS reconnaissance helpers.",
        "runtime": "Core runtime, audit, artifact, bundle, key, and control commands.",
        "storage": "Database storage management.",
        "wireless": "Wireless scanning wrappers.",
    }


def print_commandlets(runner: Runner, *, page: bool = False) -> None:
    """Print commandlets grouped under their plugin providers."""
    lines = render_commandlets(runner)
    if page:
        page_generated_text("\n".join(lines))
        return
    print("\n".join(lines))


def print_triggers(runner: Runner) -> None:
    """Print provider-owned trigger rules."""
    if not runner.registry.triggers:
        print("no triggers loaded")
        return
    states = {str(row["name"]): row for row in runner.db.trigger_states()}
    rows = []
    for trigger in sorted(runner.registry.triggers, key=lambda item: runner.registry.trigger_id(item)):
        trigger_id = runner.registry.trigger_id(trigger)
        state = states.get(trigger_id)
        rows.append(
            {
                "provider": runner.registry.trigger_provider(trigger) or "",
                "name": trigger.name,
                "topic": trigger.topic,
                "action": trigger.action_command,
                "mode": trigger.action_mode,
                "cursor": str(state["last_event_id"]) if state is not None else "0",
            }
        )
    print(
        render_console_table(
            Table(
                (
                    Column("provider", "PROVIDER"),
                    Column("name", "TRIGGER"),
                    Column("topic", "TOPIC"),
                    Column("action", "ACTION"),
                    Column("mode", "MODE"),
                    Column("cursor", "CURSOR"),
                ),
                tuple(rows),
            ),
            runner.registry.varstore.get,
        )
    )


def render_commandlets(runner: Runner) -> list[str]:
    """Return commandlets grouped under their plugin providers as a table."""
    rows = []
    for provider, commandlets in runner.registry.grouped_names().items():
        for commandlet in commandlets:
            plugin = runner.registry.plugins[commandlet]
            rows.append(
                {
                    "provider": provider,
                    "commandlet": commandlet,
                    "aliases": ", ".join(runner.registry.commandlet_aliases_for(commandlet, include_provider=False)),
                    "description": plugin.spec.description,
                }
            )
    if not rows:
        return []
    return [
        render_console_table(
            Table(
                (
                    Column("provider", "PLUGIN"),
                    Column("commandlet", "COMMANDLET"),
                    Column("aliases", "ALIASES"),
                    Column("description", "WHAT IT DOES"),
                ),
                tuple(rows),
            ),
            runner.registry.varstore.get,
        )
    ]


def page_generated_text(text: str) -> None:
    """Page built-in generated text through the system pager when available."""
    page_text(text)
