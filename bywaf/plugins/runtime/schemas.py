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
    usage="schemas [owner=framework|plugin|all] [topic=<prefix>] [detail=true] [sort=topic|-topic|owner|-owner|used|-used] [--page]",
    examples=(
        "schemas",
        "schemas owner=plugin",
        "schemas topic=web.",
        "schemas topic=web.fingerprint detail=true",
        "schemas sort=-used",
        "schemas --page",
    ),
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
        candidates = [
            "--page",
            "detail=false",
            "detail=true",
            "owner=all",
            "owner=framework",
            "owner=plugin",
            "sort=owner",
            "sort=-owner",
            "sort=topic",
            "sort=-topic",
            "sort=used",
            "sort=-used",
            "topic=",
        ]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


def parse_schema_args(args: list[str]) -> tuple[dict[str, str], bool]:
    """Parse schemas selectors."""
    selectors = {"owner": "all", "topic": "", "detail": "false", "sort": "topic"}
    page = False
    for arg in args:
        if arg == "--page":
            page = True
            continue
        key, separator, value = arg.partition("=")
        if not separator:
            raise ValueError("schemas selectors must be key=value")
        if key not in selectors:
            raise ValueError("schemas selectors must be one of: detail, owner, sort, topic")
        if key == "owner" and value not in {"all", "framework", "plugin"}:
            raise ValueError("schemas owner= must be one of: all, framework, plugin")
        if key == "detail" and value not in {"false", "true"}:
            raise ValueError("schemas detail= must be one of: false, true")
        if key == "sort" and value.lstrip("-") not in {"owner", "topic", "used"}:
            raise ValueError("schemas sort= must be one of: owner, topic, used")
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
    usage = schema_usage(context)
    selected = [row for row in rows if not topic_prefix or row[1].startswith(topic_prefix)]
    sort_key = selectors["sort"]
    descending = sort_key.startswith("-")
    key = sort_key.removeprefix("-")
    selected.sort(key=lambda item: schema_sort_value(item, usage, key), reverse=descending)
    return selected


def schema_sort_value(
    row: tuple[str, str, EventSchema],
    usage: dict[str, tuple[str, ...]],
    key: str,
) -> tuple[object, ...]:
    """Return a stable sort value for a schema row."""
    owner, topic, schema = row
    if key == "owner":
        return (owner, topic)
    if key == "used":
        return (len(usage.get(topic, ())), topic)
    return (schema.topic,)


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
    sort_key = selectors["sort"]
    sort_text = schema_sort_text(sort_key)
    lines = [f"Schemas: {scope} ({len(rows)} schemas)", sort_text, table]
    if selectors["detail"] == "true":
        lines.extend(render_schema_details(context, rows, usage))
    return "\n".join(lines)


def schema_sort_text(sort_key: str) -> str:
    """Return the operator-facing schema sort note."""
    descending = sort_key.startswith("-")
    key = sort_key.removeprefix("-")
    direction = "descending" if descending else "ascending"
    opposite = f"sort={key}" if descending else f"sort=-{key}"
    reverse = "ascending" if descending else "descending"
    return f"sorted by {key} {direction} (use {opposite} to sort {reverse})"


def render_schema_details(
    context: CommandContext,
    rows: list[tuple[str, str, EventSchema]],
    usage: dict[str, tuple[str, ...]],
) -> list[str]:
    """Render field-level detail for selected schemas."""
    lines: list[str] = []
    for owner, topic, schema in rows:
        lines.append("")
        lines.append(f"Schema detail: {topic}")
        lines.append(f"  owner: {owner}")
        lines.append(f"  version: {schema.version}")
        lines.append(f"  summary: {schema.summary}")
        used_by = ", ".join(usage.get(topic, ())) or "none"
        lines.append(f"  used by: {used_by}")
        field_rows = [
            (
                field.name,
                field.field_type,
                "yes" if field.required else "",
                ", ".join(field.allowed),
                field.description,
            )
            for field in schema.fields
        ]
        lines.append("")
        lines.append(
            render_table(
                ("FIELD", "TYPE", "REQ", "ALLOWED", "DESCRIPTION"),
                field_rows,
                cell_subjects=("variable", "value", "value", "value", ""),
                style_getter=command_context_style_getter(context),
                max_width=terminal_table_width(),
            )
        )
        if schema.notes:
            lines.append("")
            lines.append("Notes")
            lines.extend(f"  - {note}" for note in schema.notes)
    return lines


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
