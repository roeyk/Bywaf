"""Repository metadata exposure checks.

Provides bundled commandlets for detecting public source-control metadata on
HTTP endpoints.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute repository exposure checks through normal dispatch.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from bywaf.events import Event
from bywaf.findings import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option
from bywaf.plugins.http.http_probe import build_opener, target_from_text

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


class DetectionStatus(Enum):
    """Detection result vocabulary for source repository exposure checks."""

    SAFE = "safe"
    CANDIDATE = "candidate"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class GitConfigProbeResult:
    """Result from probing one endpoint for `/.git/config`."""

    base_url: str
    checked_url: str
    host: str
    port: int
    scheme: str
    status: DetectionStatus
    http_status: int | None = None
    final_url: str = ""
    elapsed_ms: int = 0
    evidence: str = ""
    error: str = ""


def run_git_config_check(
    commandlet: CommandletBase,
    context: CommandContext,
    args: list[str],
    input_events: Iterable[Event],
):
    """Run the Git config exposure check for one commandlet invocation."""
    parser = commandlet.parser()
    parser.add_argument("targets", nargs="*")
    parser.add_argument("-s", "--silent", action="store_true", default=commandlet.var_default(context, "silent", False, cast=parse_bool))
    parser.add_argument("--timeout", type=float, default=commandlet.var_default(context, "timeout", 5, cast=float))
    parser.add_argument("--user-agent", default=commandlet.var_default(context, "user-agent", "Bywaf/0.9"))
    parsed = parser.parse_args(args)

    opener = build_opener(None, None, False)
    for target in git_targets(parsed.targets, input_events):
        context.raise_if_cancelled()
        context.audit_capability("network.connect")
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
    return [dict(event.payload) for event in input_events if event.topic == "http.endpoint" and event.payload.get("url")]


def endpoint_from_target_text(target: str) -> dict[str, Any]:
    """Normalize a URL/host target using the HTTP probe parser."""
    parsed = target_from_text(target, "auto", "/")
    return {
        "url": parsed.url,
        "host": parsed.host,
        "port": parsed.port,
        "scheme": parsed.scheme,
    }


def git_config_url(base_url: str) -> str:
    """Return the canonical `/.git/config` URL for a base endpoint."""
    parsed = urllib.parse.urlparse(base_url)
    path = "/.git/config"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def probe_git_config(opener, endpoint: dict[str, Any], *, timeout: float, user_agent: str) -> GitConfigProbeResult:
    """Probe one HTTP endpoint for public `/.git/config` content."""
    base_url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    checked_url = git_config_url(base_url)
    start = time.monotonic()
    request = urllib.request.Request(checked_url, method="GET", headers={"User-Agent": user_agent})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096)
            return classify_response(endpoint, checked_url, response.status, response.geturl(), body, elapsed_ms(start))
    except urllib.error.HTTPError as exc:
        body = exc.read(4096)
        return classify_response(endpoint, checked_url, exc.code, exc.geturl(), body, elapsed_ms(start))
    except urllib.error.URLError as exc:
        return base_result(endpoint, checked_url, DetectionStatus.ERROR, elapsed_ms=elapsed_ms(start), error=str(exc.reason))


def classify_response(
    endpoint: dict[str, Any],
    checked_url: str,
    http_status: int,
    final_url: str,
    body: bytes,
    elapsed: int,
) -> GitConfigProbeResult:
    """Classify a bounded response body as exposed Git config or safe."""
    sample = body.decode("utf-8", errors="replace")
    if http_status == 200 and looks_like_git_config(sample):
        return base_result(
            endpoint,
            checked_url,
            DetectionStatus.CANDIDATE,
            http_status=http_status,
            final_url=final_url,
            elapsed_ms=elapsed,
            evidence=sample[:400],
        )
    return base_result(endpoint, checked_url, DetectionStatus.SAFE, http_status=http_status, final_url=final_url, elapsed_ms=elapsed)


def looks_like_git_config(text: str) -> bool:
    """Return whether a response sample looks like a Git config file."""
    normalized = text.lower()
    return "[core]" in normalized and "repositoryformatversion" in normalized


def base_result(
    endpoint: dict[str, Any],
    checked_url: str,
    status: DetectionStatus,
    *,
    http_status: int | None = None,
    final_url: str = "",
    elapsed_ms: int = 0,
    evidence: str = "",
    error: str = "",
) -> GitConfigProbeResult:
    """Build a result from an endpoint payload and classification fields."""
    base_url = str(endpoint.get("final_url") or endpoint.get("url") or "")
    scheme = str(endpoint.get("scheme") or urllib.parse.urlparse(base_url).scheme or "")
    host = str(endpoint.get("host") or urllib.parse.urlparse(base_url).hostname or "")
    port = int(endpoint.get("port") or default_port(scheme))
    return GitConfigProbeResult(
        base_url=base_url,
        checked_url=checked_url,
        host=host,
        port=port,
        scheme=scheme,
        status=status,
        http_status=http_status,
        final_url=final_url,
        elapsed_ms=elapsed_ms,
        evidence=evidence,
        error=error,
    )


def elapsed_ms(start: float) -> int:
    """Return elapsed milliseconds since `start`."""
    return int((time.monotonic() - start) * 1000)


def default_port(scheme: str) -> int:
    """Return the default port for an HTTP scheme."""
    return 443 if scheme == "https" else 80


def result_payload(result: GitConfigProbeResult, *, family: str = "git_expose_check", check: str = "git_config") -> dict[str, Any]:
    """Return a JSON-safe fact payload for one Git config check."""
    return {
        "family": family,
        "check": check,
        "url": result.base_url,
        "checked_url": result.checked_url,
        "host": result.host,
        "port": result.port,
        "scheme": result.scheme,
        "status": result.status.value,
        "http_status": result.http_status,
        "final_url": result.final_url,
        "elapsed_ms": result.elapsed_ms,
        "evidence": result.evidence,
        "error": result.error,
    }


def candidate_from_detection(result: GitConfigProbeResult, *, source_tool: str = "git_expose_check") -> dict[str, Any] | None:
    """Return a normalized finding candidate for exposed Git config."""
    if result.status is not DetectionStatus.CANDIDATE:
        return None
    return candidate_payload(
        title="Exposed Git repository configuration",
        finding_class="source-repository-metadata-exposure.git-config",
        severity="high",
        confidence="high",
        target={
            "scheme": result.scheme,
            "host": result.host,
            "port": str(result.port),
            "path": "/.git/config",
            "url": result.checked_url,
        },
        identifiers={"cwe": ["CWE-538"]},
        evidence=f"{result.checked_url} returned Git configuration content: {result.evidence[:200]}",
        recommendation="Remove the .git directory from deployed web roots and block access to source-control metadata paths.",
        source={"tool": source_tool, "topic": "repo.git_config.checked"},
    )


def plugin() -> Commandlet:
    """Factory used by PluginRegistry."""
    return GitExposeCheck()


def plugins() -> tuple[Commandlet, ...]:
    """Factory used by PluginRegistry for this provider's commandlets."""
    return (GitExposeCheck(), RepoExposure())
