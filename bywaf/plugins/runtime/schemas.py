"""Runtime view for registered event schemas."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import EVENT_SCHEMAS, Event, plugin_event_schemas
from bywaf.event.schemas import EventSchema
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.runtime_display import command_context_style_getter, render_table, terminal_table_width


@commandlet(
    name="schemas",
    description="List registered event schemas and commandlet usage.",
    usage="schemas [owner=framework|plugin|all] [topic=<prefix>] [--page]",
    examples=("schemas", "schemas owner=plugin", "schemas topic=web.", "schemas --page"),
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Schemas(CommandletBase):
    """Render framework and plugin-owned event schemas."""

    def run(self, context: CommandContext, args: list[str], input_events: Iterable[Event]):
        """Render schema rows."""
        del input_events
        selectors, page = parse_schema_args(args)
        rows = schema_rows(context, selectors)
        output = render_schemas(context, rows, selectors)
        if page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete schema selectors."""
        del context, args
        candidates = ["--page", "owner=all", "owner=framework", "owner=plugin", "topic="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_schema_args(args: list[str]) -> tuple[dict[str, str], bool]:
    """Parse schemas selectors."""
    selectors = {"owner": "all", "topic": ""}
    page = False
    for arg in args:
        if arg == "--page":
            page = True
            continue
        key, separator, value = arg.partition("=")
        if not separator:
            raise ValueError("schemas selectors must be key=value")
        if key not in selectors:
            raise ValueError("schemas selectors must be one of: owner, topic")
        if key == "owner" and value not in {"all", "framework", "plugin"}:
            raise ValueError("schemas owner= must be one of: all, framework, plugin")
        selectors[key] = value
    return selectors, page


def schema_rows(context: CommandContext, selectors: dict[str, str]) -> list[tuple[str, str, EventSchema]]:
    """Return selected schema rows as owner/topic/schema tuples."""
    rows: list[tuple[str, str, EventSchema]] = []
    owner = selectors["owner"]
    topic_prefix = selectors["topic"]
    if owner in {"all", "framework"}:
        rows.extend(("framework", topic, schema) for topic, schema in EVENT_SCHEMAS.items())
    if owner in {"all", "plugin"}:
        rows.extend(("plugin", topic, schema) for topic, schema in plugin_event_schemas().items())
    return [
        row
        for row in sorted(rows, key=lambda item: (item[0], item[1]))
        if not topic_prefix or row[1].startswith(topic_prefix)
    ]


def render_schemas(
    context: CommandContext,
    rows: list[tuple[str, str, EventSchema]],
    selectors: dict[str, str],
) -> str:
    """Render schema list output."""
    if not rows:
        return "Schemas: no registered schemas"
    usage = schema_usage(context)
    table_rows = [
        (
            owner,
            topic,
            schema.version,
            ", ".join(schema.required_fields),
            len(schema.fields),
            ", ".join(usage.get(topic, ())),
            schema.summary,
        )
        for owner, topic, schema in rows
    ]
    table = render_table(
        ("OWNER", "TOPIC", "VER", "REQUIRED", "FIELDS", "USED BY", "SUMMARY"),
        table_rows,
        cell_subjects=("value", "event.topic", "value", "value", "", "command", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    owner = selectors["owner"]
    topic = selectors["topic"]
    scope = f"owner={owner}" if owner != "all" else "all registered schemas"
    if topic:
        scope += f" topic={topic}"
    return f"Schemas: {scope} ({len(rows)} schemas)\n{table}"


def schema_usage(context: CommandContext) -> dict[str, tuple[str, ...]]:
    """Return commandlets that declare each schema topic in consumes/emits."""
    runner = context.metadata.get("runner")
    registry = getattr(runner, "registry", None)
    if registry is None:
        return {}
    usage: dict[str, set[str]] = {}
    for name, plugin in registry.plugins.items():
        for topic in (*plugin.spec.consumes, *plugin.spec.emits):
            usage.setdefault(topic, set()).add(name)
    return {topic: tuple(sorted(names)) for topic, names in usage.items()}


def plugins() -> tuple[Commandlet, ...]:
    """Return schema view commandlet."""
    return (Schemas(),)
