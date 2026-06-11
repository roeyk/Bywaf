"""Command orchestration for repository exposure checks.

Provides argument parsing, target collection, probe execution, event emission,
and finding publication for repository exposure commandlets.

Consumes:
- `http.endpoint` events or explicit URL command arguments.

Emits:
- `repo.git_config.checked` for Git config exposure probe results.
- `finding.candidate` for confirmed exposed repository metadata.

Used by:
- repo exposure plugin registration: delegate commandlet execution.
- tests: verify Bywaf integration around pure detection and findings logic."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bywaf.event import Event
from bywaf.plugin import CommandContext, CommandletBase, parse_bool
from bywaf.plugin import kv_to_args
from bywaf.plugins.http.probe import build_opener, target_from_text
from bywaf.plugins.http.nikto import filter_http_by_policy

from .detect import probe_git_config
from .findings import candidate_from_detection, result_payload
from .models import DetectionStatus


def run_git_config_check(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run the Git config exposure check for one commandlet invocation.

    Called by: `GitExposeCheck.run()` and `RepoExposure.run()`.

    Emits yielded `repo.git_config.checked` payloads plus persisted
    `finding.candidate` events for confirmed exposure.
    """
    parser = commandlet.parser()
    # Keep parser construction close to the commandlet invocation boundary.
    # The probe and finding modules should stay free of argparse/Bywaf context.
    # Add positional targets and Bywaf `target=value` aliases to the parser.
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--target", dest="target_options", action="append", default=[])
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", 5, cast=float))
    parser.add_argument("--user-agent", default=commandlet.var_default(context, "user-agent", "Bywaf/0.9"))
    # Convert key/value command syntax, then parse into concrete runtime values.
    parsed = parser.parse_args(normalize_value_args(args))

    # Build the HTTP opener used by the pure probe function.
    opener = build_opener(None, None, False)

    # Merge repeated target= options with positional targets.
    explicit_targets = [*parsed.target_options, *parsed.targets]

    # Resolve explicit or upstream HTTP endpoints, then apply HTTP target
    # policy before any network probe runs.
    for target in filter_http_by_policy(context, git_targets(explicit_targets, input_events)):
        context.raise_if_cancelled()

        # Record actual runtime use of the declared network capability.
        context.audit_capability("network.connect")

        # The command layer bridges pure detection to framework events: first
        # emit the observed fact, then optionally promote it to a finding.
        # Fetch and classify `/.git/config` for this endpoint.
        result = probe_git_config(opener, target, timeout=parsed.timeout, user_agent=parsed.user_agent)

        # Convert the detection result into the plugin-owned checked-event
        # payload shape.
        payload = result_payload(result, family=context.source, check="git_config")

        # Promote only candidate detections to finding.candidate.
        finding = candidate_from_detection(result, source_tool=context.source)
        if finding is not None:
            context.events.publish("finding.candidate", finding)
            context.alert(f"exposed .git/config detected at {result.checked_url}", silent=parsed.silent)
        elif result.status is DetectionStatus.ERROR:
            context.alert(f"could not check {result.base_url}: {result.error}", silent=True)
        yield payload


def git_targets(targets: list[str], input_events: Iterable[Event]) -> list[dict[str, Any]]:
    """Return normalized HTTP endpoint payloads to check.

    Called by: `run_git_config_check()` before target-policy filtering.
    """
    if targets:
        # Normalize each explicit URL/host through the HTTP probe parser.
        return [endpoint_from_target_text(target) for target in targets]

    # Pipeline use consumes only HTTP endpoint facts. Other upstream events pass
    # through the pipeline but are not meaningful for repository exposure checks.
    # Copy payloads to ordinary dicts before passing them to pure detection.
    return [dict(event.payload) for event in input_events if event.topic == "http.endpoint" and event.payload.get("url")]


def normalize_value_args(args: list[str]) -> list[str]:
    """Convert Bywaf `target=value` tokens into argparse options.

    Called by: `run_git_config_check()` before argparse parsing.
    """
    return kv_to_args(args, {"target"})


def endpoint_from_target_text(target: str) -> dict[str, Any]:
    """Normalize a URL/host target using the HTTP probe parser.

    Called by: `git_targets()` for explicit command arguments.
    """
    # Parse URL/host text with shared HTTP target rules.
    parsed = target_from_text(target, "auto", "/")
    # Return the event-like endpoint shape expected by the pure detector.
    return {
        "url": parsed.url,
        "host": parsed.host,
        "port": parsed.port,
        "scheme": parsed.scheme,
    }
