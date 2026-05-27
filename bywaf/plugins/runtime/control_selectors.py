"""Runtime-control selector resolution.

Converts user-facing selectors (`job=`, `pipeline=`, `step=`, `serial=`) into
canonical runtime ids used by control action handlers.

Used by:
- runtime.control: normalize commandlet targets.
- runtime.control_actions: display queue targets and resolve job ids."""

from __future__ import annotations

from bywaf.plugin import CommandContext, CompletionContext
from bywaf.plugins.runtime.job import job_ids
from bywaf.plugins.runtime.pipeline import pipeline_ids


def parse_target(target: str) -> tuple[str, str]:
    """Parse a `kind=id` target selector."""
    if "=" not in target:
        raise ValueError("target must be job=<id>, pipeline=<id>, step=<id>, or serial=<id>")
    kind, target_id = target.split("=", 1)
    if kind not in {"job", "pipeline", "step", "serial"} or not target_id:
        raise ValueError("target must be job=<id>, pipeline=<id>, step=<id>, or serial=<id>")
    return kind, target_id


def resolve_control_target(
    context: CommandContext,
    kind: str,
    target_id: str,
    *,
    allow_pipeline: bool,
) -> tuple[str, str]:
    """Resolve local IDs and durable serials to canonical runtime control targets."""
    runtime = context.runtime_store("control")
    if kind == "serial":
        # serial= is durable and can identify several runtime entity kinds. The
        # caller decides whether pipeline serials are meaningful for its command.
        resolved = resolve_runtime_serial_target(context, target_id)
        if resolved[0] == "pipeline" and not allow_pipeline:
            raise ValueError("signal serial= must resolve to a job or run, not a pipeline")
        return resolved
    if kind == "step":
        return "run", runtime.resolve_run_serial(target_id)
    if kind == "pipeline":
        if not allow_pipeline:
            raise ValueError("signal does not target pipelines; use job=, step=, or serial= for a job/step")
        return "pipeline", runtime.resolve_pipeline_serial(target_id)
    if kind == "job":
        return "job", resolve_job_selector(context, target_id)
    return kind, target_id


def display_target_kind(kind: str) -> str:
    """Return the user-facing selector kind for an internal runtime target."""
    return "step" if kind == "run" else kind


def resolve_runtime_serial_target(context: CommandContext, serial: str) -> tuple[str, str]:
    """Resolve a durable serial to job, run, or pipeline target coordinates."""
    runtime = context.runtime_store("control")
    job_id = runtime.job_id_for_serial(serial)
    if job_id is not None:
        return "job", job_id
    if runtime.run_serial_exists(serial):
        return "run", serial
    if any(row["pipeline_id"] == serial for row in runtime.pipelines(active_only=False)):
        return "pipeline", serial
    raise ValueError(f"serial does not identify a controllable runtime entity: {serial}")


def job_id_for_serial(context: CommandContext, serial: str) -> str | None:
    """Return local job id for a durable job serial."""
    return context.runtime_store("control").job_id_for_serial(serial)


def resolve_job_selector(context: CommandContext, value: str) -> str:
    """Resolve a local job id or durable job serial for control selectors."""
    if value.isdigit():
        return value
    resolved = job_id_for_serial(context, value)
    if resolved is None:
        raise ValueError(f"unknown job: {value}")
    return resolved


def run_serial_exists(context: CommandContext, serial: str) -> bool:
    """Return whether a durable step serial is known from events or step snapshots."""
    return context.runtime_store("control").run_serial_exists(serial)


def control_completion(context: CompletionContext, prefix: str, *, allow_pipeline: bool) -> list[str] | None:
    """Complete common runtime control selectors."""
    selectors = ("job=", "pipeline=", "step=", "serial=") if allow_pipeline else ("job=", "step=", "serial=")
    if prefix.startswith("job="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"job={job_id}" for job_id in job_ids(context) if job_id.startswith(value_prefix)]
    if allow_pipeline and prefix.startswith("pipeline="):
        value_prefix = prefix.split("=", 1)[1]
        return [
            f"pipeline={pipeline_id}"
            for pipeline_id in pipeline_ids(context)
            if pipeline_id.startswith(value_prefix)
        ]
    if prefix.startswith("step="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"step={run_id}" for run_id in run_ids(context) if run_id.startswith(value_prefix)]
    if prefix.startswith("serial="):
        value_prefix = prefix.split("=", 1)[1]
        return [f"serial={serial}" for serial in runtime_serial_ids(context) if serial.startswith(value_prefix)]
    if prefix:
        return [selector for selector in selectors if selector.startswith(prefix)]
    return list(selectors)


def run_ids(context: CompletionContext) -> list[str]:
    """Return pipeline-step IDs for completion."""
    if context.db is None:
        return []
    return [str(row["command_run_id"]) for row in context.db.runs()]


def runtime_serial_ids(context: CompletionContext) -> list[str]:
    """Return durable runtime serials for signal completion."""
    if context.db is None:
        return []
    values = []
    for serial in context.db.serials():
        if serial.startswith(("artifact-", "plugin-", "script-")):
            continue
        values.append(serial)
    return values
