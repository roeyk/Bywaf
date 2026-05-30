"""Runtime results commandlet.

Provides an operator-facing view for "what did this scan find?" over the
event ledger.  Specialized result topics, such as `port.open`, are rendered
with domain-specific tables; other topics fall back to concise inserted-topic
and representative-event summaries.

Used by:
- REPL operators: inspect the latest or selected scan results.
- runtime pipeline detail: point users from pipeline structure to results."""

from __future__ import annotations

from argparse import Namespace
from collections import Counter
from collections.abc import Iterable
import time

from bywaf.event_schemas import event_schema
from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, commandlet
from bywaf.plugins.network.portscanner_ports import PORT_SORT_KEYS, render_ports
from bywaf.plugins.runtime.job import require_job
from bywaf.repl.display.events import format_event
from bywaf.runtime_display import (
    command_context_style_getter,
    parse_runtime_sort,
    render_table,
    runtime_sort_completion_candidates,
    terminal_table_width,
)
from bywaf.style import styled_subject_text

RESULT_SCOPE_KEYS = {"all", "interval", "job", "once", "pipeline", "step", "sort"}

# `results` is an operator-facing product view, not a raw audit log.  These
# framework/UI topics are still visible through `event`, but they should never
# decide what "the latest scan result" is.
NOISE_TOPIC_PREFIXES = (
    "artifact.",
    "bundle.",
    "command.run.",
    "console.",
    "db.",
    "framework.",
    "job.",
    "key.",
    "note.",
    "plugin.capability.",
    "plugin.progress.",
    "project.",
    "report.",
    "resource.",
    "runtime.",
    "shell.",
    "trigger.",
    "watchdog.",
)
NOISE_TOPICS = {"process.run", "runtime.name.assigned"}
RESULT_VIEW_COMMANDS = {
    "artifact",
    "bundle",
    "event",
    "events",
    "job",
    "pipeline",
    "port",
    "ports",
    "report",
    "result",
    "results",
    "step",
}


@commandlet(
    name="results",
    description="Show what the latest or selected scan found.",
    usage="results [--follow] [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true] [sort=<key>]",
    examples=(
        "results",
        "results --follow",
        "results sort=port",
        "results pipeline=1",
        "results step=2",
        "results job=latest",
    ),
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class Results(CommandletBase):
    """Show scan results without exposing the raw event ledger by default."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Select a result scope and render useful inserted records."""
        del input_events
        parser = self.parser()
        parser.add_argument("--follow", action="store_true")
        parser.add_argument("--page", action="store_true")
        parsed, tokens = parser.parse_known_args(args)
        selectors = parse_results_selectors(tokens)
        context.require_foreground("result views")
        if parsed.follow:
            follow_results(context, selectors)
            return ()
        scope = select_result_scope(context, selectors)
        if not scope.events:
            context.output(no_results_message(context))
            return ()
        output = render_results(context, scope)
        if parsed.page:
            context.page_text(output)
        else:
            context.output(output)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete result scope selectors."""
        del context
        if args and args[-1].startswith("sort="):
            return runtime_sort_completion_candidates(args[-1], PORT_SORT_KEYS)
        candidates = ["--follow", "--page", "all=true", "interval=", "job=", "job=latest", "once=", "pipeline=", "step=", "sort="]
        return [candidate for candidate in candidates if candidate.startswith(prefix)]


@commandlet(
    name="result",
    description="Alias for results.",
    usage="result [--follow] [job=latest|<id>] [pipeline=<id>] [step=<id>] [all=true] [sort=<key>]",
    examples=("result", "result --follow", "result sort=port", "result pipeline=1", "result step=2"),
    capabilities=("framework.console.output", "framework.file.page"),
    database_actions=("view",),
)
class ResultAlias(Results):
    """Backwards-free synonym for the singular spelling operators try first."""


def parse_results_selectors(tokens: list[str]) -> Namespace:
    """Parse `results` selector tokens into a single runtime scope."""
    scope: dict[str, str] = {}
    sort_key = "host"
    interval = 1.0
    once = False
    for token in tokens:
        if token.startswith("--"):
            raise ValueError(f"results uses selector syntax; use key=value, not {token}")
        key, separator, value = token.partition("=")
        if not separator or not key or not value:
            raise ValueError("results selectors must be key=value")
        if key not in RESULT_SCOPE_KEYS:
            raise ValueError("results selectors must be one of: all, job, pipeline, step, sort")
        if key == "interval":
            interval = parse_results_interval(value)
        elif key == "once":
            once = parse_results_boolean(value, "once")
        elif key == "sort":
            sort_key = parse_runtime_sort(value, PORT_SORT_KEYS, "results")
        else:
            scope[key] = value
    validate_results_scope(scope)
    return Namespace(scope=scope, sort=sort_key, interval=interval, once=once)


def parse_results_interval(raw: str) -> float:
    """Parse follow polling interval seconds."""
    try:
        interval = float(raw)
    except ValueError as exc:
        raise ValueError(f"invalid results interval= value: {raw}") from exc
    if interval <= 0:
        raise ValueError("results interval= must be greater than 0")
    return interval


def parse_results_boolean(raw: str, key: str) -> bool:
    """Parse true/false selector values."""
    value = raw.casefold()
    if value in {"true", "yes", "1", "on"}:
        return True
    if value in {"false", "no", "0", "off"}:
        return False
    raise ValueError(f"results {key}= must be true or false")


def validate_results_scope(scope: dict[str, str]) -> None:
    """Reject ambiguous result scopes."""
    all_value = scope.get("all", "false")
    if all_value not in {"true", "false"}:
        raise ValueError("results all= must be true or false")
    explicit_scopes = [key for key in ("job", "pipeline", "step") if key in scope]
    if all_value == "true" and explicit_scopes:
        raise ValueError("results all=true cannot be combined with job=, pipeline=, or step=")
    if len(explicit_scopes) > 1:
        raise ValueError("results accepts only one runtime scope: job=, pipeline=, or step=")


def select_result_scope(context: CommandContext, selectors: Namespace) -> Namespace:
    """Return events for an explicit scope or the latest productive step."""
    scope = selectors.scope
    events = context.event_store("results")
    runtime = context.runtime_store("results")
    if scope.get("all") == "true":
        return Namespace(label="all results", scope={"all": "true"}, sort=selectors.sort, events=non_noise_events(events.events_matching(limit=10000)))
    if "job" in scope:
        if scope["job"] == "latest":
            return latest_result_scope(context, sort=selectors.sort)
        row = require_job(context, scope["job"])
        return Namespace(label=f"job={row['id']}", scope={"job": str(row["id"])}, sort=selectors.sort, events=non_noise_events(events.events_for_job(row["id"], limit=10000)))
    if "pipeline" in scope:
        pipeline_id = runtime.resolve_pipeline_serial(scope["pipeline"])
        return Namespace(
            label=f"pipeline={scope['pipeline']}",
            scope={"pipeline": scope["pipeline"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(pipeline_id=pipeline_id, limit=10000)),
        )
    if "step" in scope:
        run_id = runtime.resolve_run_serial(scope["step"])
        return Namespace(
            label=f"step={scope['step']}",
            scope={"step": scope["step"]},
            sort=selectors.sort,
            events=non_noise_events(events.events_matching(command_run_id=run_id, limit=10000)),
        )
    return latest_result_scope(context, sort=selectors.sort)


def latest_result_scope(context: CommandContext, *, sort: str = "host") -> Namespace:
    """Return the newest operator work scope.

    Default `results` should follow the last scan-like job the operator ran,
    even when that job is still running or found nothing.  Falling back to an
    older productive step would make the command answer a different question
    than "what did the thing I just ran find?"
    """
    events = context.event_store("results latest")
    runtime = context.runtime_store("results latest")
    for row in reversed(runtime.jobs(active_only=False)):
        if context.job_id is not None and str(row["id"]) == str(context.job_id):
            continue
        if not is_result_work_job(str(row["command_line"])):
            continue
        rows = non_noise_events(events.events_for_job(row["id"], limit=10000))
        return Namespace(label=f"latest job={row['id']}", scope={"job": str(row["id"])}, sort=sort, events=rows)
    run_aliases = runtime.run_aliases()
    for row in reversed(runtime.runs(active_only=False)):
        run_id = str(row["command_run_id"])
        rows = non_noise_events(events.events_matching(command_run_id=run_id, limit=10000))
        if rows:
            step_id = run_aliases.get(run_id, run_id)
            return Namespace(label=f"latest step={step_id}", scope={"step": step_id}, sort=sort, events=rows)
    return Namespace(label="latest results", scope={}, sort=sort, events=[])


def is_result_work_job(command_line: str) -> bool:
    """Return whether a job should own the default `results` answer."""
    command = command_line.strip().split(maxsplit=1)[0] if command_line.strip() else ""
    command = command.rsplit("/", 1)[-1]
    return command not in RESULT_VIEW_COMMANDS


def follow_results(context: CommandContext, selectors: Namespace) -> None:
    """Poll and render the selected result scope until Ctrl-C."""
    last_signature: tuple[int | None, int] | None = None
    print("following results; press Ctrl-C to stop")
    try:
        while True:
            scope = select_result_scope(context, selectors)
            signature = result_scope_signature(scope.events)
            if signature != last_signature:
                if scope.events:
                    print(render_results(context, scope), flush=True)
                else:
                    print(no_results_message(context), flush=True)
                last_signature = signature
                if selectors.once:
                    return
            elif selectors.once:
                return
            time.sleep(selectors.interval)
    except KeyboardInterrupt:
        print("stopped following results")


def result_scope_signature(events: list[Event]) -> tuple[int | None, int]:
    """Return a cheap change detector for a rendered result scope."""
    if not events:
        return (None, 0)
    return (max(event.id or 0 for event in events), len(events))


def render_results(context: CommandContext, scope: Namespace) -> str:
    """Render result-like events with specialized views where possible."""
    sections = [render_results_header(scope)]
    host_events = [event for event in scope.events if event.topic == "host.found"]
    name_events = [event for event in scope.events if event.topic == "name.resolved"]
    port_events = [event for event in scope.events if event.topic == "port.open"]
    banner_events = [event for event in scope.events if event.topic == "tcp.banner"]
    service_events = [event for event in scope.events if event.topic == "service.detected"]
    tls_events = [event for event in scope.events if event.topic == "tls.certificate"]
    route_events = [event for event in scope.events if event.topic == "network.route.hop"]
    endpoint_events = [event for event in scope.events if event.topic == "http.endpoint"]
    path_events = [event for event in scope.events if event.topic == "http.path"]
    waf_events = [event for event in scope.events if event.topic == "web.waf.detected"]
    screenshot_events = [event for event in scope.events if event.topic == "web.screenshotted_host"]
    smb_share_events = [event for event in scope.events if event.topic == "smb.share.found"]
    artifact_events = [event for event in scope.events if event.topic == "artifact.attached"]
    if host_events:
        sections.append(render_hosts_section(context, host_events))
    if name_events:
        sections.append(render_name_resolution_section(context, name_events))
    if port_events:
        sections.append(render_ports_section(context, port_events, scope))
    if banner_events:
        sections.append(render_tcp_banners_section(context, banner_events))
    if service_events:
        sections.append(render_services_section(context, service_events))
    if tls_events:
        sections.append(render_tls_certificates_section(context, tls_events))
    if route_events:
        sections.append(render_route_hops_section(context, route_events))
    if endpoint_events:
        sections.append(render_http_endpoints_section(context, endpoint_events))
    if path_events:
        sections.append(render_http_paths_section(context, path_events))
    if waf_events:
        sections.append(render_waf_section(context, waf_events))
    if screenshot_events:
        sections.append(render_screenshots_section(context, screenshot_events))
    if smb_share_events:
        sections.append(render_smb_shares_section(context, smb_share_events))
    if artifact_events:
        sections.append(render_artifacts_section(context, artifact_events))
    summarized_topics = {
        "artifact.attached",
        "host.found",
        "name.resolved",
        "port.open",
        "service.detected",
        "tcp.banner",
        "tls.certificate",
        "network.route.hop",
        "http.endpoint",
        "http.path",
        "web.waf.detected",
        "smb.share.found",
        "web.screenshotted_host",
    }
    other_events = [event for event in scope.events if event.topic not in summarized_topics]
    if other_events:
        sections.append(render_event_topic_summary(context, other_events))
        sections.append(render_representative_events(context, other_events))
    return "\n\n".join(section for section in sections if section)


def render_results_header(scope: Namespace) -> str:
    """Render the result scope and the shared schemas represented in it."""
    lines = [f"Results: {scope.label}"]
    topics = schema_backed_topics(scope.events)
    if topics:
        lines.append("Shared schemas: " + ", ".join(topics))
    return "\n".join(lines)


def schema_backed_topics(events: list[Event]) -> tuple[str, ...]:
    """Return shared event-schema topics present in this result set."""
    return tuple(sorted({event.topic for event in events if event_schema(event.topic) is not None}))


def render_hosts_section(context: CommandContext, events: list[Event]) -> str:
    """Render discovered hosts as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("name", ""),
            event.payload.get("status", ""),
            event.payload.get("scanner", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "NAME", "STATUS", "SCANNER"),
        rows,
        cell_subjects=("host", "host.name", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Hosts discovered ({len(events)})\n{table}"


def render_name_resolution_section(context: CommandContext, events: list[Event]) -> str:
    """Render name-to-address mappings as one row per original name."""
    grouped: dict[str, list[str]] = {}
    for event in events:
        name = str(event.payload.get("name") or "")
        host = event.payload.get("host")
        if host is None:
            continue
        grouped.setdefault(name, []).append(str(host))
    rows = [
        (name, ", ".join(dict.fromkeys(sorted(hosts))))
        for name, hosts in sorted(grouped.items())
    ]
    table = render_table(
        ("NAME", "RESOLVED HOSTS"),
        rows,
        cell_subjects=("host.name", "host"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Name resolutions ({len(events)})\n{table}"


def render_ports_section(context: CommandContext, events: list[Event], scope: Namespace) -> str:
    """Render delegated open-port results with the equivalent view command."""
    command = equivalent_ports_command(scope)
    command = styled_subject_text(command_context_style_getter(context), "command_line", command)
    table = render_ports(context, events, Namespace(scope=scope.scope, filters={}, sort=scope.sort))
    return f"Output of: ports\nEquivalent command: {command}\n\n{table}"


def equivalent_ports_command(scope: Namespace) -> str:
    """Return the `ports` command that would render the same result section."""
    args = [f"{key}={value}" for key, value in scope.scope.items()]
    args.append(f"sort={scope.sort}")
    if args:
        return "ports " + " ".join(args)
    return "ports"


def render_http_endpoints_section(context: CommandContext, events: list[Event]) -> str:
    """Render reachable HTTP endpoints as a compact result table."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("server", ""),
            event.payload.get("error", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "SERVER", "ERROR"),
        rows,
        cell_subjects=("url", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP endpoints ({len(events)})\n{table}"


def render_tcp_banners_section(context: CommandContext, events: list[Event]) -> str:
    """Render TCP banner probe results as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("banner", "") or event.payload.get("error", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), int(event.payload.get("port") or 0), event.id or 0))
    ]
    table = render_table(
        ("HOST", "PORT", "BANNER / ERROR"),
        rows,
        cell_subjects=("host", "port", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TCP banners ({len(events)})\n{table}"


def render_services_section(context: CommandContext, events: list[Event]) -> str:
    """Render normalized service classifications."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("protocol", ""),
            event.payload.get("service", ""),
            event.payload.get("product", "") or event.payload.get("evidence", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), int(event.payload.get("port") or 0), event.id or 0))
    ]
    table = render_table(
        ("HOST", "PORT", "PROTO", "SERVICE", "EVIDENCE"),
        rows,
        cell_subjects=("host", "port", "protocol", "value", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Services detected ({len(events)})\n{table}"


def render_tls_certificates_section(context: CommandContext, events: list[Event]) -> str:
    """Render TLS certificate metadata."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("port", ""),
            event.payload.get("subject", ""),
            event.payload.get("issuer", ""),
            event.payload.get("not_after", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), int(event.payload.get("port") or 0), event.id or 0))
    ]
    table = render_table(
        ("HOST", "PORT", "SUBJECT", "ISSUER", "VALID UNTIL"),
        rows,
        cell_subjects=("host", "port", "", "", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"TLS certificates ({len(events)})\n{table}"


def render_screenshots_section(context: CommandContext, events: list[Event]) -> str:
    """Render screenshot artifact references as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            ", ".join(str(url) for url in event.payload.get("urls", [])[:2]),
            len(event.payload.get("screenshots", [])),
            screenshot_artifact_refs(event),
            event.payload.get("tool", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "URLS", "SHOTS", "ARTIFACTS", "TOOL"),
        rows,
        cell_subjects=("host", "url", "", "artifact", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Screenshots ({len(events)})\n{table}"


def screenshot_artifact_refs(event: Event) -> str:
    """Return compact artifact references for one screenshot event."""
    refs: list[str] = []
    screenshots = event.payload.get("screenshots", [])
    if not isinstance(screenshots, list):
        return ""
    for screenshot in screenshots:
        if not isinstance(screenshot, dict):
            continue
        ref = screenshot.get("artifact_id") or screenshot.get("artifact") or screenshot.get("path")
        if ref:
            refs.append(str(ref))
    return ", ".join(refs)


def render_smb_shares_section(context: CommandContext, events: list[Event]) -> str:
    """Render SMB shares as a compact result table."""
    rows = [
        (
            event.payload.get("host", ""),
            event.payload.get("share", ""),
            event.payload.get("access", ""),
            format_bool(event.payload.get("authenticated")),
            event.payload.get("remark", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("host") or ""), str(event.payload.get("share") or ""), event.id or 0))
    ]
    table = render_table(
        ("HOST", "SHARE", "ACCESS", "AUTH", "REMARK"),
        rows,
        cell_subjects=("host", "value", "status", "", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"SMB shares ({len(events)})\n{table}"


def format_bool(value: object) -> str:
    """Format optional bools for result tables."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return ""


def render_artifacts_section(context: CommandContext, events: list[Event]) -> str:
    """Render attached artifacts as a compact result table."""
    rows = [
        (
            event.payload.get("artifact_id", ""),
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
    return f"Artifacts ({len(events)})\n{table}"


def render_route_hops_section(context: CommandContext, events: list[Event]) -> str:
    """Render route traces as a compact result table."""
    rows = [
        (
            event.payload.get("target", ""),
            event.payload.get("hop", ""),
            event.payload.get("host", "") or event.payload.get("status", ""),
            event.payload.get("ip", ""),
            format_rtt(event.payload.get("rtt_ms")),
        )
        for event in sorted(
            events,
            key=lambda event: (
                str(event.payload.get("target") or ""),
                int(event.payload.get("hop") or 0),
                event.id or 0,
            ),
        )
    ]
    table = render_table(
        ("TARGET", "HOP", "HOST / STATUS", "IP", "RTT"),
        rows,
        cell_subjects=("host", "step", "host", "host", "value"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"Route hops ({len(events)})\n{table}"


def render_http_paths_section(context: CommandContext, events: list[Event]) -> str:
    """Render HTTP path observations."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("status", ""),
            event.payload.get("title", ""),
            "yes" if event.payload.get("interesting") else "",
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "STATUS", "TITLE", "INTERESTING"),
        rows,
        cell_subjects=("url", "status", "", "status"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"HTTP paths ({len(events)})\n{table}"


def render_waf_section(context: CommandContext, events: list[Event]) -> str:
    """Render WAF or edge protection fingerprints."""
    rows = [
        (
            event.payload.get("url", ""),
            event.payload.get("vendor", ""),
            event.payload.get("product", ""),
            event.payload.get("confidence", ""),
            event.payload.get("evidence", ""),
        )
        for event in sorted(events, key=lambda event: (str(event.payload.get("url") or ""), event.id or 0))
    ]
    table = render_table(
        ("URL", "VENDOR", "PRODUCT", "CONF", "EVIDENCE"),
        rows,
        cell_subjects=("url", "value", "value", "status", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    return f"WAF signals ({len(events)})\n{table}"


def format_rtt(value: object) -> str:
    """Format one route hop round-trip time."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        return f"{value:g} ms"
    return str(value)


def no_results_message(context: CommandContext) -> str:
    """Explain an empty result view and mention active work when relevant."""
    runtime = context.runtime_store("results active jobs")
    active_jobs = [
        row
        for row in runtime.jobs(active_only=True)
        if context.job_id is None or str(row["id"]) != str(context.job_id)
    ]
    if not active_jobs:
        return "no results"
    rows = [
        (
            row["id"],
            row["status"],
            str(row["command_line"]),
        )
        for row in active_jobs[-5:]
    ]
    table = render_table(
        ("JOB", "STATUS", "COMMAND"),
        rows,
        cell_subjects=("job", "status", "command"),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )
    latest_job = active_jobs[-1]["id"]
    return (
        "no results yet; active work is still running\n"
        f"{table}\n"
        f"Try again with `results`, or inspect progress with `job {latest_job}`."
    )


def render_event_topic_summary(context: CommandContext, events: list[Event]) -> str:
    """Render inserted event topic counts."""
    counts = Counter(event.topic for event in events)
    rows = [(topic, count) for topic, count in sorted(counts.items())]
    return "Inserted events\n" + render_table(
        ("TOPIC", "COUNT"),
        rows,
        cell_subjects=("event.topic", ""),
        style_getter=command_context_style_getter(context),
        max_width=terminal_table_width(),
    )


def render_representative_events(context: CommandContext, events: list[Event], *, limit: int = 10) -> str:
    """Render a small sample of raw records for unfamiliar result topics."""
    del context
    return "Representative events\n" + "\n".join(format_event(event) for event in events[:limit])


def non_noise_events(events: list[Event]) -> list[Event]:
    """Filter lifecycle/audit noise out of operator result views."""
    return [event for event in events if not is_noise_topic(event.topic)]


def is_noise_topic(topic: str) -> bool:
    """Return whether a topic is lifecycle/audit noise for result display."""
    if event_schema(topic) is not None:
        return False
    return topic in NOISE_TOPICS or topic.startswith(NOISE_TOPIC_PREFIXES)


def plugins() -> tuple[Commandlet, ...]:
    """Return plural and singular result commandlets."""
    return (Results(), ResultAlias())
