"""Convenience kill/cancel commandlets for jobs and pipelines."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet
from bywaf.plugins.runtime.job import cancel_job, job_ids, kill_job, require_job
from bywaf.plugins.runtime.pipeline import cancel_pipeline, kill_pipeline, pipeline_ids


class Control(CommandletBase):
    """Shared implementation for `kill` and `cancel` convenience commandlets."""

    action: str

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Dispatch `job=<id>` or `pipeline=<id>` to the specific manager."""
        parser = self.parser()
        parser.add_argument("target")
        parser.add_argument("--force", action="store_true")
        parsed = parser.parse_args(args)
        context.require_foreground(f"{self.action} commands")
        kind, target_id = parse_target(parsed.target)
        match (self.action, kind):
            case ("cancel", "job"):
                cancel_job(context, require_job(context, target_id))
            case ("cancel", "pipeline"):
                cancel_pipeline(context, target_id)
            case ("kill", "job"):
                kill_job(context, require_job(context, target_id), force=parsed.force)
            case ("kill", "pipeline"):
                kill_pipeline(context, target_id, force=parsed.force)
            case _:
                raise ValueError(f"unsupported target: {parsed.target}")
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete `job=<id>` and `pipeline=<id>` selectors."""
        selectors = ("job=", "pipeline=")
        if prefix.startswith("job="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"job={job_id}" for job_id in job_ids(context) if job_id.startswith(value_prefix)]
        if prefix.startswith("pipeline="):
            value_prefix = prefix.split("=", 1)[1]
            return [
                f"pipeline={pipeline_id}"
                for pipeline_id in pipeline_ids(context)
                if pipeline_id.startswith(value_prefix)
            ]
        if prefix:
            return [selector for selector in selectors if selector.startswith(prefix)]
        return list(selectors)


@commandlet(
    name="kill",
    description="Hard-terminate a job or pipeline.",
    usage="kill [--force] <job=id|pipeline=id>",
    examples=("kill job=1", "kill --force pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Kill(Control):
    """Hard-terminate a job or pipeline."""

    action = "kill"


@commandlet(
    name="cancel",
    description="Request cooperative cancellation for a job or pipeline.",
    usage="cancel <job=id|pipeline=id>",
    examples=("cancel job=1", "cancel pipeline=pipeline-..."),
    capabilities=("db.raw", "framework.console.output", "framework.job.control", "framework.pipeline.control"),
)
@argument("target", "job=<id> or pipeline=<id>", completion=CompletionSpec("choice", ("job=", "pipeline=")))
class Cancel(Control):
    """Request cooperative cancellation for a job or pipeline."""

    action = "cancel"


def parse_target(target: str) -> tuple[str, str]:
    """Parse a `kind=id` target selector."""
    if "=" not in target:
        raise ValueError("target must be job=<id> or pipeline=<id>")
    kind, target_id = target.split("=", 1)
    if kind not in {"job", "pipeline"} or not target_id:
        raise ValueError("target must be job=<id> or pipeline=<id>")
    return kind, target_id


def plugin() -> Commandlet:
    """Return the first commandlet when loaded as a single plugin entry."""
    return Kill()


def plugins() -> tuple[Commandlet, ...]:
    """Return all commandlets provided by this module."""
    return (Kill(), Cancel())
