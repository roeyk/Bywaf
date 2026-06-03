"""Policy decision reporting for audit commandlets.

Summarizes framework `policy.evaluated` events so operators can review what
was allowed, warned, or blocked without duplicating policy enforcement logic.

Used by:
- runtime.audit: implement `audit list policy`."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime_display import render_table, terminal_table_width
from bywaf.time_format import format_operator_timestamp

from .selectors import selected_events

POLICY_SELECTOR_KEYS = {"decision", "job", "pipeline", "plugin", "serial", "since", "step", "target", "until"}
POLICY_DECISIONS = ("allow", "warn", "deny", "block")


def policy_decision_rows(context: CommandContext, selectors: dict[str, str]) -> list[dict[str, str]]:
    """Return printable rows for recorded policy decisions."""
    unsupported = set(selectors) - POLICY_SELECTOR_KEYS
    if unsupported:
        raise ValueError(f"unsupported audit policy selector: {sorted(unsupported)[0]}")
    query = {key: value for key, value in selectors.items() if key in {"job", "pipeline", "serial", "since", "step", "until"}}
    query["topic"] = "policy.evaluated"
    events = selected_events(context, query, limit=100000)
    return [policy_decision_row(event) for event in events if policy_event_matches(event, selectors)]


def policy_selector_completion_candidates(context: object, prefix: str) -> list[str]:
    """Return `audit list policy` selector value completions."""
    db = getattr(context, "db", None)
    if db is None:
        return []
    key, separator, value_prefix = prefix.partition("=")
    if separator != "=":
        return [f"{candidate}=" for candidate in sorted(POLICY_SELECTOR_KEYS) if f"{candidate}=".startswith(prefix)]
    values = policy_selector_values(db, key)
    return [f"{key}={value}" for value in values if value.startswith(value_prefix)]


def policy_selector_values(db: object, key: str) -> list[str]:
    """Return value candidates for one policy report selector."""
    if key == "decision":
        return sorted({*POLICY_DECISIONS, *policy_decision_values(db)})
    if key == "plugin":
        return policy_plugin_values(db)
    if key == "target":
        return policy_target_completion_values(db)
    if key == "step":
        return list(getattr(db, "run_aliases")().values())
    if key == "pipeline":
        return list(getattr(db, "pipeline_aliases")().values())
    if key == "job":
        return [str(row["id"]) for row in getattr(db, "jobs")()]
    if key == "serial":
        return list(getattr(db, "serials")())
    return []


def policy_decision_values(db: object) -> list[str]:
    """Return observed policy decision labels."""
    return sorted(
        {
            str(event.payload.get("decision"))
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            if event.payload.get("decision")
        }
    )


def policy_plugin_values(db: object) -> list[str]:
    """Return observed commandlet names from policy decisions."""
    return sorted(
        {
            policy_commandlet(event)
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            if policy_commandlet(event) != "-"
        }
    )


def policy_target_completion_values(db: object) -> list[str]:
    """Return observed before/after targets from policy decisions."""
    return sorted(
        {
            target
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            for target in policy_target_values(event)
        }
    )


def policy_event_matches(event: Event, selectors: dict[str, str]) -> bool:
    """Return whether a policy event matches operator report selectors."""
    if (decision := selectors.get("decision")) and str(event.payload.get("decision", "")) != decision:
        return False
    if (plugin := selectors.get("plugin")) and policy_commandlet(event) != plugin:
        return False
    if target := selectors.get("target"):
        haystack = " ".join(policy_target_values(event))
        if target not in haystack:
            return False
    return True


def policy_decision_row(event: Event) -> dict[str, str]:
    """Build one printable policy decision report row."""
    payload = event.payload
    before = format_targets(payload.get("before"))
    after = format_targets(payload.get("after"))
    warnings = payload.get("warnings", ())
    repairs = payload.get("repairs", ())
    return {
        "Time": format_operator_timestamp(event.created_at),
        "Decision": str(payload.get("decision") or "-"),
        "Commandlet": policy_commandlet(event),
        "Before": before,
        "After": after,
        "Notes": format_notes(warnings, repairs),
        "Step": str(payload.get("command_run_id") or event.command_run_id or "-"),
        "Job": str(payload.get("job_id") or "-"),
    }


def policy_commandlet(event: Event) -> str:
    """Return the commandlet associated with a policy decision."""
    return str(event.payload.get("commandlet") or event.source or "-")


def policy_target_values(event: Event) -> list[str]:
    """Return target strings from policy before/after payloads."""
    return [*target_values(event.payload.get("before")), *target_values(event.payload.get("after"))]


def target_values(value: object) -> list[str]:
    """Extract target values from a policy payload section."""
    if not isinstance(value, dict):
        return []
    targets = value.get("targets")
    if not isinstance(targets, list):
        return []
    return [str(target) for target in targets]


def format_targets(value: object) -> str:
    """Return a compact target list for table display."""
    targets = target_values(value)
    return ", ".join(targets) if targets else "-"


def format_notes(warnings: object, repairs: object) -> str:
    """Return warnings and repairs in one operator-facing table cell."""
    parts = [*string_values(warnings), *(f"repair:{repair}" for repair in string_values(repairs))]
    return "; ".join(parts) if parts else "-"


def string_values(value: object) -> Iterable[str]:
    """Yield string values from a list-like audit payload value."""
    if not isinstance(value, list):
        return ()
    return (str(item) for item in value)


def format_policy_decisions(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width policy decision report table."""
    if not rows:
        return "No policy decisions matched."
    columns = ["Time", "Decision", "Commandlet", "Before", "After", "Notes", "Step", "Job"]
    table_rows = [tuple(row[column] for column in columns) for row in rows]
    return render_table(tuple(columns), table_rows, max_width=max(terminal_table_width(), 160))
