"""Runtime commandlet for naming jobs, pipelines, and command runs."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet


@commandlet(
    name="name",
    description="Show or assign names for jobs, pipelines, and command runs.",
    usage="name <run=id|pipeline=id|job=id> [value=name]",
    examples=(
        "name run=hostscanner-... value=localhost sweep",
        "name pipeline=pipeline-... value=client subnet scan",
        "name job=12 value=background listener",
    ),
    capabilities=("db.raw", "framework.console.output"),
)
@argument("selector", "run=, pipeline=, or job= selector", completion=CompletionSpec("choice", ("run=", "pipeline=", "job=")))
@argument("value", "optional value= name", required=False)
class Name(CommandletBase):
    """Display or assign user-facing runtime entity names."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Show an existing name or assign a new one."""
        del input_events
        selectors = parse_name_selectors(args)
        target_type, target_id = selected_target(selectors)
        if "value" in selectors:
            context.require_db("name").publish(
                "runtime.name.assigned",
                {
                    "target_type": target_type,
                    "target_id": target_id,
                    "name": selectors["value"],
                    "job_id": target_id if target_type == "job" else None,
                    "pipeline_id": target_id if target_type == "pipeline" else None,
                    "command_run_id": target_id if target_type == "run" else None,
                },
                "framework",
                pipeline_id=target_id if target_type == "pipeline" else None,
                command_run_id=target_id if target_type == "run" else None,
            )
            context.output(f"named {target_type}={target_id} {selectors['value']}")
            return ()
        display_name = context.require_db("name").runtime_names().get((target_type, target_id))
        context.output(f"{target_type}={target_id} name={display_name or ''}".rstrip())
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete runtime selectors and value=."""
        if prefix.startswith("run="):
            return [f"run={row['command_run_id']}" for row in context.db.runs()] if context.db else []
        if prefix.startswith("pipeline="):
            return [f"pipeline={row['pipeline_id']}" for row in context.db.pipelines()] if context.db else []
        if prefix.startswith("job="):
            return [f"job={row['id']}" for row in context.db.jobs()] if context.db else []
        if prefix.startswith("value="):
            return []
        if not args:
            return ["run=", "pipeline=", "job="]
        return ["value="]


def parse_name_selectors(args: list[str]) -> dict[str, str]:
    """Parse name command selectors, allowing final value= to consume the rest."""
    selectors: dict[str, str] = {}
    index = 0
    while index < len(args):
        arg = args[index]
        if "=" not in arg:
            raise ValueError(f"invalid name selector: {arg}")
        key, value = arg.split("=", 1)
        if key == "value":
            value = " ".join([value, *args[index + 1:]]).strip()
            index = len(args)
        else:
            index += 1
        if key not in {"run", "pipeline", "job", "value"}:
            raise ValueError(f"unknown name selector: {key}")
        if not value:
            raise ValueError(f"name selector {key}= requires a value")
        selectors[key] = value
    selected_target(selectors)
    return selectors


def selected_target(selectors: dict[str, str]) -> tuple[str, str]:
    """Return the single selected target type and id."""
    targets = [key for key in ("run", "pipeline", "job") if key in selectors]
    if len(targets) != 1:
        raise ValueError("name requires exactly one run=, pipeline=, or job= selector")
    target_type = targets[0]
    return target_type, selectors[target_type]


def plugin() -> Commandlet:
    """Return the runtime name commandlet."""
    return Name()
