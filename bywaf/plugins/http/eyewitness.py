"""EyeWitness wrapper commandlet.

Provides a bundled plugin implementation and CommandSpec metadata for the
external EyeWitness screenshot tool.

Consumes:
- `http.endpoint` events or explicit URL arguments.

Emits:
- `eyewitness.screenshot` for raw screenshot files.
- `web.screenshotted_host` for normalized host-to-screenshot artifact groups.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from bywaf.config import Settings
from bywaf.event.schema_objects import ScreenshottedHost
from bywaf.event import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool
from bywaf.plugin.process.artifacts import proc_artifact_ref
from bywaf.plugin import kv_to_args, reject_option_equals
from bywaf.plugins.http.nikto import (
    dedupe_targets,
    filter_http_by_policy,
    target_from_endpoint_event,
    target_payload_from_text,
)

DEFAULTS = {
    "binary": "eyewitness",
    "output-dir": "",
    "silent": "false",
    "source": "all",
    "timeout": "600",
}

SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
VALUE_OPTION_KEYS = {"binary", "output-dir", "source", "timeout"}


@commandlet(
    name="eyewitness",
    description="Run EyeWitness against HTTP endpoints and attach screenshots.",
    usage="eyewitness [options] [target ...]",
    examples=(
        "eyewitness https://example.test/",
        "http_probe https://example.test/ | eyewitness",
    ),
)
@option("binary", "EyeWitness executable", "eyewitness", completion="path")
@option("output-dir", "directory for EyeWitness output", completion="path")
@option("silent", "suppress screenshot alerts", "false")
@option("source", "endpoint source", "all", ("all", "explicit"))
@option("timeout", "seconds for the EyeWitness run", "600")
class EyeWitness(CommandletBase):
    """Run EyeWitness and publish screenshot artifacts.

    Called by: PluginRegistry/runner dispatch for the `eyewitness` commandlet.

    Used by: `Screenshotter`, which subclasses this wrapper to expose the
    friendlier screenshotter command name while reusing the same process and
    artifact handling.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Run EyeWitness for explicit targets or upstream HTTP endpoints.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        parser = self.parser()
        # Build the command parser at the commandlet boundary. The lower-level
        # helpers receive concrete values instead of knowing about argparse.
        parser.add_argument("targets", nargs="*")
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--binary", default=self.var_default(context, "binary", "eyewitness"))
        parser.add_argument("--output-dir", default=self.var_default(context, "output-dir", ""))
        parser.add_argument("--source", choices=("all", "explicit"), default=self.var_default(context, "source", "all"))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 600, cast=float))
        # Reject --key=value for path-like options so Bywaf key=value parsing
        # stays predictable and completion-friendly.
        reject_option_equals(
            args,
            VALUE_OPTION_KEYS,
            usage="usage: eyewitness [binary=path] [output-dir=path] [source=all|explicit] [timeout=seconds] [--silent] [target ...]",
        )
        # Convert Bywaf value tokens such as binary=... into argparse options.
        parsed = parser.parse_args(kv_to_args(args, VALUE_OPTION_KEYS))

        # Resolve explicit URLs and/or upstream http.endpoint events, then
        # apply the global HTTP target policy before invoking the external
        # process.
        targets = filter_http_by_policy(
            context,
            eyewitness_targets(parsed.targets, input_events, parsed.source),
        )
        if not targets:
            # Emit a structured diagnostic rather than silently doing nothing.
            context.events.publish(
                "tool.error",
                {
                    "tool": "eyewitness",
                    "severity": "warning",
                    "message": "no HTTP endpoints selected for EyeWitness",
                    "source": parsed.source,
                },
            )
            return ()

        # Choose a durable output directory before process execution so
        # screenshots and temporary target lists share the same run location.
        output_dir = eyewitness_output_dir(context, str(parsed.output_dir or ""))
        run_eyewitness(context, parsed, targets, output_dir)
        return ()


def run_eyewitness(context: CommandContext, parsed: Any, targets: list[dict[str, Any]], output_dir: Path) -> None:
    """Run EyeWitness once and publish screenshot events for produced files.

    Called by: `EyeWitness.run()` after target resolution and output-dir
    selection.
    """
    # Record actual runtime use of the declared network capability before
    # launching the scanner.
    context.audit_capability("network.connect")

    # Ensure the external tool has a destination directory for reports and
    # screenshots.
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build the shell-free argv vector and optional multi-target input file.
    argv, target_file = eyewitness_argv(str(parsed.binary), targets, output_dir)
    try:
        # Execute EyeWitness through the framework process service so stdout,
        # stderr, return code, timeout, and policy are handled uniformly.
        result = context.process.run(argv, timeout=float(parsed.timeout))
    except FileNotFoundError as exc:
        # Missing binaries are setup errors, so publish a system diagnostic and
        # raise a user-visible command error.
        publish_tool_problem(context, "system.error", "eyewitness", "EyeWitness executable not found", exc)
        raise ValueError(f"EyeWitness executable not found: {parsed.binary}") from exc
    except subprocess.TimeoutExpired as exc:
        # Timeouts are tool-run failures; keep the framework session alive and
        # avoid publishing screenshot facts.
        publish_tool_problem(context, "tool.error", "eyewitness", "EyeWitness run timed out", exc)
        return
    except OSError as exc:
        # Other process launch failures should be visible but should not crash
        # the entire pipeline.
        publish_tool_problem(context, "system.error", "eyewitness", "could not execute EyeWitness", exc)
        return
    finally:
        # The generated target list is just process input. Evidence comes from
        # screenshot files attached below, so clean the temporary list promptly.
        if target_file is not None:
            target_file.unlink(missing_ok=True)

    # Walk the output tree for screenshot-like files created by EyeWitness.
    screenshots = screenshot_files(output_dir)

    # Preserve raw process output as an artifact only when the run failed or no
    # screenshots were found; successful screenshot artifacts are the evidence.
    proc_artifact = proc_artifact_ref(context) if not result.ok or not screenshots else {}
    if not result.ok:
        # Publish nonzero process status with stdout/stderr and optional
        # process-output artifact details for later audit.
        context.events.publish(
            "tool.error",
            {
                "tool": "eyewitness",
                "severity": "error",
                "message": f"EyeWitness exited with status {result.returncode}",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                **proc_artifact,
            },
        )

    # Attach each screenshot as an artifact and publish the raw screenshot
    # event. The list comprehension keeps the emitted payloads for grouping.
    screenshot_payloads = [
        publish_screenshot(context, screenshot, output_dir, targets, silent=bool(parsed.silent))
        for screenshot in screenshots
    ]

    # Publish normalized per-host screenshot inventory facts for reports and
    # inventory views.
    publish_screenshotted_hosts(context, screenshot_payloads)
    if not screenshots:
        # No screenshot files is useful diagnostic information even when the
        # process returned success.
        context.events.publish(
            "tool.error",
            {
                "tool": "eyewitness",
                "severity": "warning",
                "message": "EyeWitness produced no screenshot files",
                "output_dir": str(output_dir),
                **proc_artifact,
            },
        )


def eyewitness_argv(binary: str, targets: list[dict[str, Any]], output_dir: Path) -> tuple[list[str], Path | None]:
    """Build an EyeWitness argv vector and optional temporary target file.

    Called by: `run_eyewitness()` before process execution.
    """
    # Start with the common EyeWitness web-mode invocation.
    argv = [binary, "--web", "--no-prompt", "-d", str(output_dir)]
    if len(targets) == 1:
        # EyeWitness accepts a single URL directly on argv.
        argv.extend(["--single", str(targets[0]["url"])])
        return argv, None

    # EyeWitness expects many targets through a file. Keep this shell-free and
    # return the file path so the caller can remove it after execution.
    target_file = output_dir / "bywaf-eyewitness-targets.txt"
    target_file.write_text("\n".join(str(target["url"]) for target in targets) + "\n", encoding="utf-8")
    argv.extend(["-f", str(target_file)])
    return argv, target_file


def eyewitness_output_dir(context: CommandContext, explicit: str) -> Path:
    """Return a durable output directory for EyeWitness artifacts.

    Called by: `EyeWitness.run()` after parsing command options.
    """
    if explicit:
        # Respect operator-provided output locations.
        return Path(explicit).expanduser()

    # Use command run ID when available so pipeline runs get stable artifact
    # directories; fall back to job/session identifiers for direct execution.
    run_id = context.command_run_id or str(context.job_id or "session")
    return Settings().state_dir / "eyewitness" / run_id


def eyewitness_targets(targets: list[str], input_events: Iterable[Event], source: str) -> list[dict[str, Any]]:
    """Resolve EyeWitness targets from explicit args or `http.endpoint` events.

    Called by: `EyeWitness.run()` before target-policy filtering.
    """
    resolved: list[dict[str, Any]] = []
    if targets:
        # Normalize explicit URL/host text through the shared Nikto HTTP target
        # helpers used by other external wrappers.
        resolved.extend(target_payload_from_text(target) for target in targets)
        if source == "explicit":
            # In explicit mode, ignore upstream pipeline endpoints.
            return dedupe_targets(resolved)
    if source == "all":
        # Pipeline mode consumes normalized HTTP endpoint events.
        resolved.extend(target_from_endpoint_event(event) for event in input_events if event.topic == "http.endpoint")

    # Drop failed target conversions and de-duplicate by URL.
    return dedupe_targets(target for target in resolved if target)


def screenshot_files(output_dir: Path) -> list[Path]:
    """Return screenshot-like files produced by EyeWitness.

    Called by: `run_eyewitness()` after process execution.
    """
    if not output_dir.exists():
        return []

    # Recursively scan EyeWitness output and keep known browser-image formats.
    return sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in SCREENSHOT_EXTENSIONS
    )


def publish_screenshot(
    context: CommandContext,
    screenshot: Path,
    output_dir: Path,
    targets: list[dict[str, Any]],
    *,
    silent: bool,
) -> dict[str, Any]:
    """Attach and publish one screenshot artifact event.

    Called by: `run_eyewitness()` for every produced screenshot file.
    """
    # Record actual runtime use of the declared filesystem capability before
    # reading and attaching the screenshot file.
    context.audit_capability("filesystem.read")

    # The screenshot file remains discoverable even if artifact storage is not
    # available; successful attachment enriches the event with artifact metadata.
    # Start with the raw file path and target details that remain useful even
    # when artifact attachment fails.
    payload: dict[str, Any] = {
        **screenshot_target_payload(screenshot, targets),
        "tool": "eyewitness",
        "file": str(screenshot),
        "relative_path": str(screenshot.relative_to(output_dir)),
        "targets": targets,
    }
    try:
        # Copy the screenshot into the framework artifact store and add stable
        # artifact identifiers to the event payload.
        artifact = context.artifacts.attach_file(
            screenshot,
            name=f"eyewitness-{screenshot.name}",
            note="EyeWitness screenshot",
        )
        payload.update(
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "artifact_sha256": artifact.sha256,
            }
        )
    except (RuntimeError, ValueError) as exc:
        # Keep the screenshot event but record why durable artifact attachment
        # failed.
        payload["artifact_error"] = str(exc)
        context.events.publish(
            "tool.error",
            {
                "tool": "eyewitness",
                "severity": "warning",
                "message": "screenshot was not attached as an artifact",
                "file": str(screenshot),
                "error": str(exc),
            },
        )

    # Publish both machine-readable event data and compact operator feedback.
    context.events.publish("eyewitness.screenshot", payload)
    context.alert(f"captured screenshot {screenshot.name}", level="artifact", silent=silent)
    return payload


def screenshot_target_payload(screenshot: Path, targets: list[dict[str, Any]]) -> dict[str, str]:
    """Return normalized target fields for a screenshot payload.

    Called by: `publish_screenshot()` before artifact attachment.
    """
    # EyeWitness does not guarantee a one-to-one screenshot-to-target mapping in
    # the filesystem, so use the first target as the best available attribution.
    target = targets[0] if targets else {}
    return {
        "url": str(target.get("url") or screenshot),
        "host": str(target.get("host") or ""),
    }


def publish_screenshotted_hosts(context: CommandContext, screenshots: list[dict[str, Any]]) -> None:
    """Publish normalized per-host screenshot artifact groups.

    Called by: `run_eyewitness()` after raw screenshot events are published.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for screenshot in screenshots:
        # Group screenshots by host and URL so inventory/report views can show
        # one concise row per endpoint.
        host = str(screenshot.get("host") or "")
        url = str(screenshot.get("url") or "")
        grouped.setdefault((host, url), []).append(screenshot_reference(screenshot))
    for (host, url), refs in grouped.items():
        # Convert grouped refs into the shared web.screenshotted_host schema.
        payload = ScreenshottedHost(
            host=host,
            urls=[url] if url else [],
            screenshots=refs,
            tool="eyewitness",
        ).to_payload()
        context.events.publish(ScreenshottedHost.__topic__, payload)


def screenshot_reference(payload: dict[str, Any]) -> dict[str, str]:
    """Return the compact artifact/file reference stored on ScreenshottedHost.

    Called by: `publish_screenshotted_hosts()` while grouping screenshots.
    """
    keys = ("artifact_id", "artifact_name", "artifact_sha256", "file", "relative_path", "url")
    # Keep only populated fields and stringify them for JSON/event stability.
    return {key: str(payload[key]) for key in keys if payload.get(key)}


def publish_tool_problem(context: CommandContext, topic: str, tool: str, message: str, exc: BaseException) -> None:
    """Publish a normalized operational problem for an external wrapper.

    Called by: `run_eyewitness()` for launch, timeout, and execution failures.
    """
    # Store the exception class separately from its message so reports can
    # group operational failure types without parsing free text.
    context.events.publish(
        topic,
        {
            "tool": tool,
            "severity": "error",
            "message": message,
            "exception": exc.__class__.__name__,
            "error": str(exc),
        },
    )


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return EyeWitness()
