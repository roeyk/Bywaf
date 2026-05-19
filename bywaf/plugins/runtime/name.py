"""Runtime commandlet for naming jobs, pipelines, and command runs."""

from __future__ import annotations

from collections.abc import Iterable

from bywaf.events import Event
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, CompletionContext, CompletionSpec, argument, commandlet


@commandlet(
    name="name",
    description="Show or assign names for jobs, pipelines, and command runs.",
    usage="name <run=id|pipeline=id|job=id> [name text|text=name]",
    examples=(
        "name run=1 localhost sweep",
        "name pipeline=1 client subnet scan",
        "name job=12 background listener",
    ),
    capabilities=("framework.console.output",),
)
@argument("selector", "run=, pipeline=, or job= selector", completion=CompletionSpec("choice", ("run=", "pipeline=", "job=")))
@argument("value", "optional name text", required=False)
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
        target_type, target_id = selected_target(context, selectors)
        if "value" in selectors:
            context.event_store("name").publish(
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
        display_name = context.runtime_store("name").runtime_names().get((target_type, target_id))
        context.output(f"{target_type}={target_id} name={display_name or ''}".rstrip())
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete runtime selectors."""
        if prefix.startswith("run="):
            return [f"run={value}" for value in sorted(context.db.run_aliases().values(), key=int)] if context.db else []
        if prefix.startswith("pipeline="):
            return [f"pipeline={value}" for value in sorted(context.db.pipeline_aliases().values(), key=int)] if context.db else []
        if prefix.startswith("job="):
            return [f"job={row['id']}" for row in context.db.jobs()] if context.db else []
        if not args:
            return ["run=", "pipeline=", "job="]
        return []


def parse_name_selectors(args: list[str]) -> dict[str, str]:
    """Parse target selectors and optional trailing name text."""
    selectors: dict[str, str] = {}
    index = 0
    while index < len(args):
        arg = args[index]
        if "=" not in arg:
            selectors["value"] = " ".join(args[index:]).strip()
            break
        key, value = arg.split("=", 1)
        if key == "text":
            value = " ".join([value, *args[index + 1:]]).strip()
            index = len(args)
        else:
            index += 1
        if key not in {"run", "pipeline", "job", "text"}:
            raise ValueError(f"unknown name selector: {key}")
        if not value:
            raise ValueError(f"name selector {key}= requires a value")
        selectors["value" if key == "text" else key] = value
    selected_target(None, selectors)
    return selectors


def selected_target(context: CommandContext | None, selectors: dict[str, str]) -> tuple[str, str]:
    """Return the single selected target type and id."""
    targets = [key for key in ("run", "pipeline", "job") if key in selectors]
    if len(targets) != 1:
        raise ValueError("name requires exactly one run=, pipeline=, or job= selector")
    target_type = targets[0]
    target_id = selectors[target_type]
    if context is not None and target_type == "run":
        target_id = context.runtime_store("name").resolve_run_serial(target_id)
    if context is not None and target_type == "pipeline":
        target_id = context.runtime_store("name").resolve_pipeline_serial(target_id)
    return target_type, target_id


def plugin() -> Commandlet:
    """Return the runtime name commandlet."""
    return Name()
