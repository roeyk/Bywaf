"""Repository metadata exposure checks.

Provides bundled commandlets for detecting public source-control metadata on
HTTP endpoints.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute repository exposure checks through normal dispatch.
"""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option

from .command import endpoint_from_target_text, git_targets, parse_bool, run_git_config_check
from .detect import base_result, default_port, git_config_url, looks_like_git_config, probe_git_config
from .findings import candidate_from_detection, result_payload
from .models import DetectionStatus, GitConfigProbeResult

# Stable package facade for the repository-exposure family. The split modules
# keep detection, orchestration, and finding mapping testable in isolation while
# this package remains the provider entry point.
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
)
@option("silent", "suppress exposure alerts", "false")
@option("timeout", "request timeout seconds", "5")
@option("user-agent", "HTTP User-Agent", "Bywaf/0.9")
class GitExposeCheck(CommandletBase):
    """Check one or more HTTP endpoints for exposed Git repository metadata.

    Called by: PluginRegistry/runner dispatch for the `git_expose_check`
    commandlet.

    Delegates to: `run_git_config_check()` for parsing, target selection,
    probing, event payload creation, and finding promotion.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Check explicit targets or upstream `http.endpoint` events.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        # Delegate execution to command.py so this provider module stays as the
        # stable registry/import surface rather than owning orchestration logic.
        yield from run_git_config_check(self, context, args, input_events)


@commandlet(
    name="repo_exposure",
    description="Orchestrate repository exposure checks against HTTP endpoints.",
    usage="repo_exposure [options] [target ...]",
    examples=(
        "repo_exposure https://example.test/",
        "http_probe https://example.test/ | repo_exposure",
    ),
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
        """Run repository exposure checks for explicit or upstream targets.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        # Currently this orchestrator runs the same Git config check and tags
        # emitted payloads with the broader `repo_exposure` family name.
        yield from run_git_config_check(self, context, args, input_events)


def plugin() -> Commandlet:
    """Return the default commandlet object loaded by PluginRegistry."""
    return GitExposeCheck()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlet objects loaded by PluginRegistry for this provider."""
    return (GitExposeCheck(), RepoExposure())
