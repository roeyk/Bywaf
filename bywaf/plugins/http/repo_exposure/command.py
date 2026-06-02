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
from bywaf.plugin import CommandContext, CommandletBase
from bywaf.plugins._args import key_value_to_long_options
from bywaf.plugins.http.http_probe import build_opener, target_from_text
from bywaf.plugins.http.nikto import filter_http_payloads_by_policy

from .detect import probe_git_config
from .findings import candidate_from_detection, result_payload
from .models import DetectionStatus


def run_git_config_check(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run the Git config exposure check for one commandlet invocation."""
    parser = commandlet.parser()
    # Keep parser construction close to the commandlet invocation boundary.
    # The probe and finding modules should stay free of argparse/Bywaf context.
    parser.add_argument("targets", nargs="*")
    parser.add_argument("--target", dest="target_options", action="append", default=[])
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", 5, cast=float))
    parser.add_argument("--user-agent", default=commandlet.var_default(context, "user-agent", "Bywaf/0.9"))
    parsed = parser.parse_args(normalize_value_args(args))

    opener = build_opener(None, None, False)
    explicit_targets = [*parsed.target_options, *parsed.targets]
    for target in filter_http_payloads_by_policy(context, git_targets(explicit_targets, input_events)):
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
        # The command layer bridges pure detection to framework events: first
        # emit the observed fact, then optionally promote it to a finding.
        result = probe_git_config(opener, target, timeout=parsed.timeout, user_agent=parsed.user_agent)
        payload = result_payload(result, family=context.source, check="git_config")
        finding = candidate_from_detection(result, source_tool=context.source)
        if finding is not None:
            context.events.publish("finding.candidate", finding)
            context.alert(f"exposed .git/config detected at {result.checked_url}", silent=parsed.silent)
        elif result.status is DetectionStatus.ERROR:
            context.alert(f"could not check {result.base_url}: {result.error}", silent=True)
        yield payload


def parse_bool(value: str | bool) -> bool:
    """Parse bool-like commandlet variable values."""
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def git_targets(targets: list[str], input_events: Iterable[Event]) -> list[dict[str, Any]]:
    """Return normalized HTTP endpoint payloads to check."""
    if targets:
        return [endpoint_from_target_text(target) for target in targets]
    # Pipeline use consumes only HTTP endpoint facts. Other upstream events pass
    # through the pipeline but are not meaningful for repository exposure checks.
    return [dict(event.payload) for event in input_events if event.topic == "http.endpoint" and event.payload.get("url")]


def normalize_value_args(args: list[str]) -> list[str]:
    """Convert Bywaf `target=value` tokens into argparse options."""
    return key_value_to_long_options(args, {"target"})


def endpoint_from_target_text(target: str) -> dict[str, Any]:
    """Normalize a URL/host target using the HTTP probe parser."""
    parsed = target_from_text(target, "auto", "/")
    return {
        "url": parsed.url,
        "host": parsed.host,
        "port": parsed.port,
        "scheme": parsed.scheme,
    }
