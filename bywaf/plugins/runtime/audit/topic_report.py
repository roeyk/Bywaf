"""Topic-contract reporting for audit commandlets.

Summarizes `plugin.topic.policy` events so operators can review topic-contract
warnings and enforcement decisions without inspecting raw JSON events.

Used by:
- runtime.audit: implement `audit list topics`."""

from __future__ import annotations

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import render_table, terminal_table_width
from bywaf.time_format import format_operator_timestamp

from .selectors import selected_events

TOPIC_POLICY_SELECTOR_KEYS = {"decision", "job", "pipeline", "plugin", "reason", "serial", "since", "step", "topic", "until"}
TOPIC_POLICY_DECISIONS = ("audit", "warn", "enforce")
TOPIC_POLICY_REASONS = ("undeclared", "unregistered")


def topic_policy_rows(context: CommandContext, selectors: dict[str, str]) -> list[dict[str, str]]:
    """Return printable rows for recorded topic-contract policy decisions."""
    unsupported = set(selectors) - TOPIC_POLICY_SELECTOR_KEYS
    if unsupported:
        raise ValueError(f"unsupported audit topics selector: {sorted(unsupported)[0]}")
    query = {key: value for key, value in selectors.items() if key in {"job", "pipeline", "serial", "since", "step", "until"}}
    query["topic"] = "plugin.topic.policy"
    events = selected_events(context, query, limit=100000)
    return [topic_policy_row(event) for event in events if topic_policy_event_matches(event, selectors)]


def topic_policy_candidates(context: object, prefix: str) -> list[str]:
    """Return `audit list topics` selector value completions."""
    db = getattr(context, "db", None)
    if db is None:
        return []
    key, separator, value_prefix = prefix.partition("=")
    if separator != "=":
        return [f"{candidate}=" for candidate in sorted(TOPIC_POLICY_SELECTOR_KEYS) if f"{candidate}=".startswith(prefix)]
    values = topic_policy_selector_values(db, key)
    return [f"{key}={value}" for value in values if value.startswith(value_prefix)]


def topic_policy_selector_values(db: object, key: str) -> list[str]:
    """Return value candidates for one topic-contract report selector."""
    if key == "decision":
        return sorted({*TOPIC_POLICY_DECISIONS, *topic_policy_payload_values(db, "decision")})
    if key == "reason":
        return sorted({*TOPIC_POLICY_REASONS, *topic_policy_payload_values(db, "reason")})
    if key == "plugin":
        return sorted({topic_policy_commandlet(event) for event in topic_policy_events(db) if topic_policy_commandlet(event) != "-"})
    if key == "topic":
        return topic_policy_payload_values(db, "topic")
    if key == "step":
        return list(getattr(db, "run_aliases")().values())
    if key == "pipeline":
        return list(getattr(db, "pipeline_aliases")().values())
    if key == "job":
        return [str(row["id"]) for row in getattr(db, "jobs")()]
    if key == "serial":
        return list(getattr(db, "serials")())
    return []


def topic_policy_payload_values(db: object, key: str) -> list[str]:
    """Return observed topic-policy payload values for one key."""
    return sorted({str(event.payload.get(key)) for event in topic_policy_events(db) if event.payload.get(key)})


def topic_policy_events(db: object) -> list[Event]:
    """Return topic-policy audit events."""
    return list(getattr(db, "events_for_topic")("plugin.topic.policy", limit=100000))


def topic_policy_event_matches(event: Event, selectors: dict[str, str]) -> bool:
    """Return whether a topic-policy event matches operator report selectors."""
    if (decision := selectors.get("decision")) and str(event.payload.get("decision", "")) != decision:
        return False
    if (reason := selectors.get("reason")) and str(event.payload.get("reason", "")) != reason:
        return False
    if (topic := selectors.get("topic")) and str(event.payload.get("topic", "")) != topic:
        return False
    if (plugin := selectors.get("plugin")) and topic_policy_commandlet(event) != plugin:
        return False
    return True


def topic_policy_row(event: Event) -> dict[str, str]:
    """Build one printable topic-policy report row."""
    payload = event.payload
    return {
        "Time": format_operator_timestamp(event.created_at),
        "Decision": str(payload.get("decision") or "-"),
        "Reason": str(payload.get("reason") or "-"),
        "Topic": str(payload.get("topic") or "-"),
        "Commandlet": topic_policy_commandlet(event),
        "Message": str(payload.get("message") or "-"),
        "Step": str(payload.get("command_run_id") or event.command_run_id or "-"),
        "Job": str(payload.get("job_id") or "-"),
    }


def topic_policy_commandlet(event: Event) -> str:
    """Return the commandlet associated with a topic-policy decision."""
    return str(event.payload.get("commandlet") or event.source or "-")


def format_topic_policy_rows(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width topic-contract policy table."""
    if not rows:
        return "No topic policy decisions matched."
    columns = ["Time", "Decision", "Reason", "Topic", "Commandlet", "Message", "Step", "Job"]
    table_rows = [tuple(row[column] for column in columns) for row in rows]
    return render_table(tuple(columns), table_rows, max_width=max(terminal_table_width(), 180))
