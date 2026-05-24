"""Repository metadata exposure checks.

Provides bundled commandlets for detecting public source-control metadata on
HTTP endpoints.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute repository exposure checks through normal dispatch.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option

from .command import endpoint_from_target_text, git_targets, parse_bool, run_git_config_check
from .detect import base_result, default_port, git_config_url, looks_like_git_config, probe_git_config
from .findings import candidate_from_detection, result_payload
from .models import DetectionStatus, GitConfigProbeResult

__all__ = [
    "DEFAULTS",
    "REPO_EXPOSURE_CHECKS",
    "DetectionStatus",
    "GitConfigProbeResult",
    "GitExposeCheck",
    "RepoExposure",
    "base_result",
    "candidate_from_detection",
    "default_port",
    "endpoint_from_target_text",
    "git_config_url",
    "git_targets",
    "looks_like_git_config",
    "parse_bool",
    "plugin",
    "plugins",
    "probe_git_config",
    "result_payload",
    "run_git_config_check",
]

DEFAULTS = {
    "silent": "false",
    "timeout": 5,
    "user-agent": "Bywaf/0.9",
}
REPO_EXPOSURE_CHECKS = ("git_config",)


@commandlet(
    name="git_expose_check",
    description="Check HTTP endpoints for exposed .git/config metadata.",
    usage="git_expose_check [options] [target ...]",
    examples=(
        "git_expose_check https://example.test/",
        "http_probe https://example.test/ | git_expose_check",
    ),
    consumes=("http.endpoint",),
    emits=("repo.git_config.checked", "finding.candidate"),
    capabilities=("db.write:finding.candidate", "framework.console.alert", "network.connect"),
)
@option("silent", "suppress exposure alerts", "false")
@option("timeout", "request timeout seconds", "5")
@option("user-agent", "HTTP User-Agent", "Bywaf/0.9")
class GitExposeCheck(CommandletBase):
    """Check one or more HTTP endpoints for exposed Git repository metadata."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Check explicit targets or upstream `http.endpoint` events."""
        yield from run_git_config_check(self, context, args, input_events)


@commandlet(
    name="repo_exposure",
    description="Orchestrate repository exposure checks against HTTP endpoints.",
    usage="repo_exposure [options] [target ...]",
    examples=(
        "repo_exposure https://example.test/",
        "http_probe https://example.test/ | repo_exposure",
    ),
    consumes=("http.endpoint",),
    emits=("repo.git_config.checked", "finding.candidate"),
    capabilities=("db.write:finding.candidate", "framework.console.alert", "network.connect"),
)
@option("silent", "suppress exposure alerts", "false")
@option("timeout", "request timeout seconds", "5")
@option("user-agent", "HTTP User-Agent", "Bywaf/0.9")
class RepoExposure(CommandletBase):
    """Orchestrator commandlet for source repository exposure checks.

    This is still a normal commandlet. It coordinates related checks and marks
    emitted payloads with `family` and `check` fields. The family currently
    includes `/.git/config`.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run repository exposure checks for explicit or upstream targets."""
        yield from run_git_config_check(self, context, args, input_events)


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return GitExposeCheck()


def plugins() -> tuple[Commandlet, ...]:
    """Factory used by PluginRegistry for this provider's commandlets."""
    return (GitExposeCheck(), RepoExposure())
