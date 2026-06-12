"""WafW00f-backed WAF detection commandlet.

This plugin wraps the external `wafw00f` binary and normalizes its output into
Bywaf's shared `web.waf.detected` schema. Raw stdout/stderr are retained by the
framework process service as process transcript artifacts.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bywaf.event import Event
from bywaf.event.schema_objects import WebWafDetected
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    ProcessResult,
    argument,
    commandlet,
    kv_to_args,
    option,
    parse_bool,
    reject_option_equals,
)
from bywaf.plugins.http.targets import HttpTarget, endpoint_http_targets
from bywaf.plugins.target_policy import filter_targets_by_host


DEFAULT_TIMEOUT = 90.0


@dataclass(frozen=True, slots=True)
class WafSignal:
    """One parsed WafW00f detection result.

    Constructed by: `parse_wafw00f_output()` from WafW00f stdout/stderr text.
    Used by: `Waf.run_target()` to publish a schema-backed detection event.
    """

    vendor: str
    product: str | None
    evidence: str
    confidence: str


@commandlet(
    name="waf",
    description="Run WafW00f and publish normalized WAF detection facts.",
    usage="waf [options] [target ...]",
    examples=(
        "waf https://example.com",
        "http_probe https://example.com | waf",
    ),
    consumes=("http.endpoint",),
    emits=("web.waf.detected", "tool.error"),
    capabilities=(
        "artifact.write",
        "db.read:http.endpoint",
        "db.write:process.run",
        "db.write:tool.error",
        "db.write:web.waf.detected",
        "framework.console.alert",
        "framework.process.run",
        "network.connect",
    ),
    database_actions=("view", "write"),
)
@argument("target", "HTTP or HTTPS target URL. Repeat for multiple targets or omit for pipeline input.", required=False)
@option("binary", "WafW00f executable path or command name.", default="wafw00f")
@option("timeout", "Maximum seconds to allow each WafW00f process.", default=str(int(DEFAULT_TIMEOUT)))
@option("silent", "Suppress operator alerts.", default="false")
class Waf(CommandletBase):
    """Wrap WafW00f without exposing subprocess or parsing details to users."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run WafW00f for explicit targets or upstream HTTP endpoints."""
        cfg = parse_args(self.parser(), args)
        # Accept both direct operator targets and pipeline-produced HTTP
        # endpoint events so `waf URL` and `http_probe URL | waf` share one
        # execution path.
        targets = endpoint_http_targets(cfg.targets, input_events)
        # Apply the framework's target-scope policy before starting any
        # external process. The lambda exposes the normalized host field that
        # scope filters compare against.
        scoped_targets = filter_targets_by_host(context, targets, lambda target: target.host)
        if not scoped_targets:
            publish_tool_error(context, "wafw00f", None, "no HTTP targets supplied")
            return ()

        for target in scoped_targets:
            context.raise_if_cancelled()
            # Audit the network capability next to the external tool launch.
            # WafW00f performs the HTTP probing, but Bywaf still records this
            # commandlet as the component that requested network access.
            context.audit_capability("network.connect")
            self.run_target(context, cfg, target)
        return ()

    def run_target(self, context: CommandContext, cfg: "WafConfig", target: HttpTarget) -> None:
        """Run WafW00f for one normalized target and publish any detection."""
        argv = (cfg.binary, target.url)
        try:
            # Delegate subprocess execution to the framework process service.
            # That service handles capability policy, timeout enforcement,
            # secret redaction, and process transcript artifact creation.
            result = context.process.run(argv, timeout=cfg.timeout)
        except FileNotFoundError:
            publish_tool_error(context, cfg.binary, target, f"{cfg.binary} executable was not found")
            return
        except (OSError, RuntimeError) as exc:
            publish_tool_error(context, cfg.binary, target, str(exc))
            return

        if not result.ok:
            publish_tool_error(context, cfg.binary, target, failed_process_message(result))
            return

        # WafW00f is still the source of truth for fingerprinting; Bywaf only
        # extracts a small structured signal from the tool's human output.
        signal = parse_wafw00f_output(result.stdout, result.stderr)
        if signal is None:
            return

        # Publish through the schema dataclass so field names and topic shape
        # stay aligned with the shared event contract.
        detection = WebWafDetected(
            url=target.url,
            host=target.host,
            vendor=signal.vendor,
            product=signal.product,
            evidence=signal.evidence[:512],
            confidence=signal.confidence,
            scanner="wafw00f",
        )
        context.events.publish_object(detection)
        context.alert(f"detected {detection.vendor} WAF signal at {target.url}", silent=cfg.silent)


@dataclass(frozen=True, slots=True)
class WafConfig:
    """Parsed runtime configuration for `waf`.

    Constructed by: `parse_args()` from framework-provided commandlet tokens.
    Used by: `Waf.run()` and `Waf.run_target()` while invoking WafW00f.
    """

    targets: list[str]
    binary: str
    timeout: float
    silent: bool


def parse_args(parser: argparse.ArgumentParser, args: list[str]) -> WafConfig:
    """Parse commandlet arguments into a small configuration object."""
    option_keys = {"binary", "silent", "timeout"}
    # The parser accepts normal argparse flags after `kv_to_args()` translates
    # Bywaf's compact key=value option syntax into flag/value pairs.
    parser.add_argument("target", nargs="*", help="HTTP or HTTPS target URL")
    parser.add_argument("--binary", default="wafw00f")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-s", "--silent", action="store_true", default=False)
    # Keep binary=..., timeout=..., and silent=... as the supported compact
    # syntax. Other option=value tokens are rejected before argparse can treat
    # them as positional targets.
    reject_option_equals(
        args,
        option_keys,
        usage="usage: waf [binary=path] [timeout=seconds] [--silent] [target ...]",
    )
    parsed = parser.parse_args(kv_to_args(args, option_keys))
    return WafConfig(
        targets=list(parsed.target),
        binary=str(parsed.binary),
        timeout=parsed.timeout,
        silent=parse_bool(parsed.silent),
    )


DETECTION_PATTERNS = (
    # Examples seen in WafW00f output include "The site ... is behind Cloudflare
    # (Cloudflare Inc.) WAF." and "behind ModSecurity WAF". The parser treats
    # these phrases as evidence while keeping the exact stdout line in payloads.
    re.compile(r"\bis behind (?P<vendor>.+?)(?:\s*\((?P<product>[^)]+)\))?\s+WAF\b", re.IGNORECASE),
    re.compile(r"\bbehind the (?P<vendor>.+?) WAF\b", re.IGNORECASE),
)


def parse_wafw00f_output(stdout: str, stderr: str = "") -> WafSignal | None:
    """Return the first WafW00f WAF signal parsed from process output."""
    # Search stdout first and stderr second while preserving the exact line as
    # evidence. Some wrappers emit diagnostics on stderr even for useful runs.
    text = "\n".join(part for part in (stdout, stderr) if part).strip()
    if not text:
        return None
    lowered = text.casefold()
    if "no waf detected" in lowered:
        return None

    for line in text.splitlines():
        signal = parse_detection_line(line)
        if signal is not None:
            return signal
    return None


def parse_detection_line(line: str) -> WafSignal | None:
    """Parse one WafW00f output line into a normalized signal."""
    for pattern in DETECTION_PATTERNS:
        match = pattern.search(line)
        if match is None:
            continue
        # WafW00f may report "Vendor (Product) WAF" or just "Vendor WAF".
        # Store both fields, using the vendor as product when the product
        # capture is absent so downstream displays have a stable value.
        vendor = clean_vendor(match.group("vendor"))
        product = clean_vendor(match.groupdict().get("product") or vendor)
        return WafSignal(vendor=vendor, product=product, evidence=line.strip(), confidence="high")
    return None


def clean_vendor(value: str) -> str:
    """Normalize a WafW00f vendor/product capture."""
    cleaned = value.strip(" ,:;")
    return re.sub(r"\s+", " ", cleaned)


def failed_process_message(result: ProcessResult) -> str:
    """Return a bounded diagnostic for a failed WafW00f process."""
    detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
    return f"wafw00f failed with exit status {result.returncode}: {detail[:300]}"


def publish_tool_error(context: CommandContext, tool: str, target: HttpTarget | None, message: str) -> None:
    """Publish a structured tool error for wrapper setup/runtime failures."""
    payload: dict[str, Any] = {"tool": tool, "error": message}
    if target is not None:
        payload.update({"url": target.url, "host": target.host})
    context.events.publish("tool.error", payload)


def plugin() -> Commandlet:
    """Return the commandlet loaded by PluginRegistry."""
    return Waf()
