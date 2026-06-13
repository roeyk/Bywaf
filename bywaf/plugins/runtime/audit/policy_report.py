"""Policy decision reporting for audit commandlets.

Summarizes framework `policy.evaluated` events so operators can review what
was allowed, warned, or blocked without duplicating policy enforcement logic.

Used by:
- runtime.audit: implement `audit list policy`."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.runtime.display import render_table, terminal_table_width
from bywaf.time_format import format_operator_timestamp

from .selectors import selected_events

POLICY_SELECTOR_KEYS = {"decision", "job", "pipeline", "plugin", "serial", "since", "step", "target", "until"}
POLICY_DECISIONS = ("allow", "warn", "deny", "block")


def policy_decision_rows(context: CommandContext, selectors: dict[str, str]) -> list[dict[str, str]]:
    """Return printable rows for recorded policy decisions.

    Called by: the runtime audit commandlet after parsing `audit list policy`
    selectors from the operator.
    """
    unsupported = set(selectors) - POLICY_SELECTOR_KEYS
    if unsupported:
        raise ValueError(f"unsupported audit policy selector: {sorted(unsupported)[0]}")
    # Runtime selectors are handled by the shared event selector helper. The
    # policy-specific selectors below are applied after query so their matching
    # rules can inspect structured before/after policy payloads.
    query = {key: value for key, value in selectors.items() if key in {"job", "pipeline", "serial", "since", "step", "until"}}
    query["topic"] = "policy.evaluated"
    events = selected_events(context, query, limit=100000)
    return [policy_decision_row(event) for event in events if policy_event_matches(event, selectors)]


def policy_candidates(context: object, prefix: str) -> list[str]:
    """Return `audit list policy` selector value completions.

    Called by: plugin argument completion when the current commandlet is
    `audit list policy`.
    """
    db = getattr(context, "db", None)
    if db is None:
        return []
    key, separator, value_prefix = prefix.partition("=")
    if separator != "=":
        return [f"{candidate}=" for candidate in sorted(POLICY_SELECTOR_KEYS) if f"{candidate}=".startswith(prefix)]
    values = policy_selector_values(db, key)
    return [f"{key}={value}" for value in values if value.startswith(value_prefix)]


def policy_selector_values(db: object, key: str) -> list[str]:
    """Return value candidates for one policy report selector.

    Called by: `policy_candidates()` after it has parsed `key=<prefix>` from
    the partially typed command line.
    """
    # POLICY_SELECTOR_VALUE_LOADERS is a dispatch table defined below. It
    # replaces a selector if/elif ladder and keeps each selector's value source
    # visible in one place for future audit-report extensions.
    loader = POLICY_SELECTOR_VALUE_LOADERS.get(key)
    return loader(db) if loader is not None else []


def policy_decision_completion_values(db: object) -> list[str]:
    """Return built-in and observed decision values for completion.

    Called by: `POLICY_SELECTOR_VALUE_LOADERS` for `decision=...`.
    """
    return sorted({*POLICY_DECISIONS, *policy_decision_values(db)})


def policy_step_values(db: object) -> list[str]:
    """Return friendly command-run aliases for policy selector completion.

    Called by: `POLICY_SELECTOR_VALUE_LOADERS` for `step=...`.
    """
    return list(getattr(db, "run_aliases")().values())


def policy_pipeline_values(db: object) -> list[str]:
    """Return friendly pipeline aliases for policy selector completion.

    Called by: `POLICY_SELECTOR_VALUE_LOADERS` for `pipeline=...`.
    """
    return list(getattr(db, "pipeline_aliases")().values())


def policy_job_values(db: object) -> list[str]:
    """Return job ids for policy selector completion.

    Called by: `POLICY_SELECTOR_VALUE_LOADERS` for `job=...`.
    """
    return [str(row["id"]) for row in getattr(db, "jobs")()]


def policy_serial_values(db: object) -> list[str]:
    """Return event serial values for policy selector completion.

    Called by: `POLICY_SELECTOR_VALUE_LOADERS` for `serial=...`.
    """
    return list(getattr(db, "serials")())


def policy_decision_values(db: object) -> list[str]:
    """Return observed policy decision labels.

    Used by: selector completion so custom or future policy decisions observed
    in the DB appear alongside the built-in decision constants.
    """
    return sorted(
        {
            str(event.payload.get("decision"))
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            if event.payload.get("decision")
        }
    )


def policy_plugin_values(db: object) -> list[str]:
    """Return observed commandlet names from policy decisions.

    Used by: selector completion for `plugin=...`.
    """
    return sorted(
        {
            policy_commandlet(event)
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            if policy_commandlet(event) != "-"
        }
    )


def policy_target_completion_values(db: object) -> list[str]:
    """Return observed before/after targets from policy decisions.

    Used by: selector completion for `target=...`.
    """
    return sorted(
        {
            target
            for event in getattr(db, "events_for_topic")("policy.evaluated", limit=100000)
            for target in policy_target_values(event)
        }
    )


# Dispatch table consumed by policy_selector_values(). Each entry maps one
# supported selector key to the cheapest source of completion candidates:
# constants, policy event payloads, runtime aliases, job rows, or serial rows.
POLICY_SELECTOR_VALUE_LOADERS: dict[str, Callable[[object], list[str]]] = {
    "decision": policy_decision_completion_values,
    "plugin": policy_plugin_values,
    "target": policy_target_completion_values,
    "step": policy_step_values,
    "pipeline": policy_pipeline_values,
    "job": policy_job_values,
    "serial": policy_serial_values,
}


def policy_event_matches(event: Event, selectors: dict[str, str]) -> bool:
    """Return whether a policy event matches operator report selectors.

    Called by: `policy_decision_rows()` after broad event selection has already
    narrowed by job, pipeline, serial, time, or step.
    """
    # Policy payload matching is intentionally substring-based for targets so
    # operators can search partially normalized URLs/hosts from policy repairs.
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
    """Build one printable policy decision report row.

    Called by: `policy_decision_rows()` for every matching `policy.evaluated`
    event before the table renderer receives fixed string columns.
    """
    payload = event.payload
    # The policy event stores before/after target sets as nested payloads. The
    # row flattens them for a fixed-width table while preserving notes about
    # warnings and automatic repairs.
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
    """Return the commandlet associated with a policy decision.

    Used by: row rendering, selector matching, and selector completion.
    """
    return str(event.payload.get("commandlet") or event.source or "-")


def policy_target_values(event: Event) -> list[str]:
    """Return target strings from policy before/after payloads.

    Used by: target selector matching and completion. Both pre-policy and
    post-repair targets are searchable because either may be what the operator
    remembers from the attempted command.
    """
    return [*target_values(event.payload.get("before")), *target_values(event.payload.get("after"))]


def target_values(value: object) -> list[str]:
    """Extract target values from a policy payload section.

    Called by: `policy_target_values()` and `format_targets()` for the nested
    `before` and `after` policy payload sections.
    """
    if not isinstance(value, dict):
        return []
    targets = value.get("targets")
    if not isinstance(targets, list):
        return []
    return [str(target) for target in targets]


def format_targets(value: object) -> str:
    """Return a compact target list for table display.

    Used by: `policy_decision_row()` to flatten nested target lists into one
    fixed-width table cell.
    """
    targets = target_values(value)
    return ", ".join(targets) if targets else "-"


def format_notes(warnings: object, repairs: object) -> str:
    """Return warnings and repairs in one operator-facing table cell.

    Used by: `policy_decision_row()` so warning text and automatic repair notes
    stay attached to the same policy decision row.
    """
    # Repairs are prefixed to distinguish policy rewrites from warning text
    # while preserving the compact one-cell table shape.
    parts = [*string_values(warnings), *(f"repair:{repair}" for repair in string_values(repairs))]
    return "; ".join(parts) if parts else "-"


def string_values(value: object) -> Iterable[str]:
    """Yield string values from a list-like audit payload value.

    Used by: `format_notes()` for warning and repair arrays that may be absent
    or malformed in older events.
    """
    if not isinstance(value, list):
        return ()
    return (str(item) for item in value)


def format_policy_decisions(rows: list[dict[str, str]]) -> str:
    """Return a fixed-width policy decision report table.

    Called by: the runtime audit commandlet after row selection. This is the
    final operator-facing rendering step for `audit list policy`.
    """
    if not rows:
        return "No policy decisions matched."
    columns = ["Time", "Decision", "Commandlet", "Before", "After", "Notes", "Step", "Job"]
    # Render rows in column order explicitly so callers can build dictionaries
    # without depending on insertion order or table-renderer internals.
    table_rows = [tuple(row[column] for column in columns) for row in rows]
    return render_table(tuple(columns), table_rows, max_width=max(terminal_table_width(), 160))
