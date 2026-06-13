"""Topic-contract reporting for audit commandlets.

Summarizes `plugin.topic.policy` events so operators can review topic-contract
warnings and enforcement decisions without inspecting raw JSON events.

Used by:
- runtime.audit: implement `audit list topics`."""

from __future__ import annotations

from collections.abc import Callable

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime.display import render_table, terminal_table_width
from bywaf.time_format import format_operator_timestamp

from .selectors import selected_events

TOPIC_POLICY_SELECTOR_KEYS = {"decision", "job", "pipeline", "plugin", "reason", "serial", "since", "step", "topic", "until"}
TOPIC_POLICY_DECISIONS = ("audit", "warn", "enforce")
TOPIC_POLICY_REASONS = ("undeclared", "unregistered")


def topic_policy_rows(context: CommandContext, selectors: dict[str, str]) -> list[dict[str, str]]:
    """Return printable rows for recorded topic-contract policy decisions.

    Called by: `runtime.audit` when handling `audit list topics`.
    """
    unsupported = set(selectors) - TOPIC_POLICY_SELECTOR_KEYS
    if unsupported:
        raise ValueError(f"unsupported audit topics selector: {sorted(unsupported)[0]}")
    # selected_events() owns runtime selectors such as job/pipeline/step/time
    # bounds. Topic-policy-specific selectors are applied below against payload
    # fields after the event query returns.
    query = {key: value for key, value in selectors.items() if key in {"job", "pipeline", "serial", "since", "step", "until"}}
    query["topic"] = "plugin.topic.policy"
    events = selected_events(context, query, limit=100000)
    return [topic_policy_row(event) for event in events if topic_policy_event_matches(event, selectors)]


def topic_policy_candidates(context: object, prefix: str) -> list[str]:
    """Return `audit list topics` selector value completions.

    Called by: the audit commandlet completion path.
    """
    db = getattr(context, "db", None)
    if db is None:
        return []
    key, separator, value_prefix = prefix.partition("=")
    if separator != "=":
        # No selector value yet: complete selector keys in `key=` form.
        return [f"{candidate}=" for candidate in sorted(TOPIC_POLICY_SELECTOR_KEYS) if f"{candidate}=".startswith(prefix)]
    # A selector key is present: complete values from built-in enums and
    # observed audit events.
    values = topic_policy_selector_values(db, key)
    return [f"{key}={value}" for value in values if value.startswith(value_prefix)]


def topic_policy_selector_values(db: object, key: str) -> list[str]:
    """Return value candidates for one topic-contract report selector.

    Called by: `topic_policy_candidates()` after parsing `key=value_prefix`.
    """
    # TOPIC_POLICY_SELECTOR_VALUE_LOADERS is a dispatch table defined below.
    # It replaces the selector if/elif ladder and makes each completion source
    # explicit for future topic-contract audit selectors.
    loader = TOPIC_POLICY_SELECTOR_VALUE_LOADERS.get(key)
    return loader(db) if loader is not None else []


def topic_policy_decision_values(db: object) -> list[str]:
    """Return built-in and observed topic-policy decisions for completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `decision=...`.
    """
    return sorted({*TOPIC_POLICY_DECISIONS, *topic_policy_payload_values(db, "decision")})


def topic_policy_reason_values(db: object) -> list[str]:
    """Return built-in and observed topic-policy reasons for completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `reason=...`.
    """
    return sorted({*TOPIC_POLICY_REASONS, *topic_policy_payload_values(db, "reason")})


def topic_policy_plugin_values(db: object) -> list[str]:
    """Return observed commandlet names for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `plugin=...`.
    """
    return sorted({topic_policy_commandlet(event) for event in topic_policy_events(db) if topic_policy_commandlet(event) != "-"})


def topic_policy_topic_values(db: object) -> list[str]:
    """Return observed topic names for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `topic=...`.
    """
    return topic_policy_payload_values(db, "topic")


def topic_policy_step_values(db: object) -> list[str]:
    """Return friendly command-run aliases for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `step=...`.
    """
    return list(getattr(db, "run_aliases")().values())


def topic_policy_pipeline_values(db: object) -> list[str]:
    """Return friendly pipeline aliases for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `pipeline=...`.
    """
    return list(getattr(db, "pipeline_aliases")().values())


def topic_policy_job_values(db: object) -> list[str]:
    """Return job ids for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `job=...`.
    """
    return [str(row["id"]) for row in getattr(db, "jobs")()]


def topic_policy_serial_values(db: object) -> list[str]:
    """Return event serial values for topic-policy completion.

    Called by: `TOPIC_POLICY_SELECTOR_VALUE_LOADERS` for `serial=...`.
    """
    return list(getattr(db, "serials")())


def topic_policy_payload_values(db: object, key: str) -> list[str]:
    """Return observed topic-policy payload values for one key.

    Called by: completion helpers for selectors whose values are mostly learned
    from prior `plugin.topic.policy` events.
    """
    return sorted({str(event.payload.get(key)) for event in topic_policy_events(db) if event.payload.get(key)})


def topic_policy_events(db: object) -> list[Event]:
    """Return topic-policy audit events.

    Called by: completion value helpers. The audit list command uses
    `selected_events()` instead so runtime scope selectors remain consistent
    with other audit reports.
    """
    return list(getattr(db, "events_for_topic")("plugin.topic.policy", limit=100000))


# Dispatch table consumed by topic_policy_selector_values(). Each selector key
# is mapped to the cheapest source of completion candidates: built-in enums,
# topic-policy payload values, runtime aliases, job rows, or serial rows.
TOPIC_POLICY_SELECTOR_VALUE_LOADERS: dict[str, Callable[[object], list[str]]] = {
    "decision": topic_policy_decision_values,
    "reason": topic_policy_reason_values,
    "plugin": topic_policy_plugin_values,
    "topic": topic_policy_topic_values,
    "step": topic_policy_step_values,
    "pipeline": topic_policy_pipeline_values,
    "job": topic_policy_job_values,
    "serial": topic_policy_serial_values,
}


def topic_policy_event_matches(event: Event, selectors: dict[str, str]) -> bool:
    """Return whether a topic-policy event matches operator report selectors.

    Called by: `topic_policy_rows()` after runtime selectors have already
    narrowed the event query.
    """
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
    """Build one printable topic-policy report row.

    Called by: `topic_policy_rows()` for each matching policy event.
    """
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
    """Return the commandlet associated with a topic-policy decision.

    Called by: filtering, completion, and row rendering. The payload commandlet
    wins; event source is the fallback for older or manually seeded events.
    """
    return str(event.payload.get("commandlet") or event.source or "-")


def format_topic_policy_rows(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width topic-contract policy table.

    Called by: `runtime.audit` after `topic_policy_rows()`.
    """
    if not rows:
        return "No topic policy decisions matched."
    columns = ["Time", "Decision", "Reason", "Topic", "Commandlet", "Message", "Step", "Job"]
    # Keep column order explicit instead of relying on dict iteration; audit
    # reports are easier to compare when the table shape is stable.
    table_rows = [tuple(row[column] for column in columns) for row in rows]
    return render_table(tuple(columns), table_rows, max_width=max(terminal_table_width(), 180))
