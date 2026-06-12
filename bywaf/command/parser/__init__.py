"""Command-line parsing helpers for commandlet execution.

Provides parsing for pipelines, framework selector flags, at-file expansion,
variable expansion, and commandlet argument normalization.

Used by:
- runner: turns REPL/CLI command text into executable commandlet invocations.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- resource script loading: parses commands loaded from script files."""


from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass

from ...varstore import VarStore
from .variables import expand_variables_in_text as expand_variables_in_text
from .selectors import (
    commandlet_owns_text_selector,
    peel_background_marker,
    peel_context_selectors,
    peel_final_text_selector,
)
from ..pipeline_syntax import (
    peel_pipeline_background as peel_pipeline_background,
    peel_pipeline_name_prefix as peel_pipeline_name_prefix,
    split_pipeline_raw as split_pipeline_raw,
)


@dataclass(frozen=True, slots=True)
class CommandInvocation:
    """Parsed commandlet invocation plus framework-owned execution selectors.

    This represents one executable command after shell text has been normalized.
    Constructed by: `parse_invocation()` after peeling Bywaf selectors away
    from plugin-owned args.
    Used by: runner execution and `build_context()` to choose the commandlet,
    replay source, background behavior, display name, and approval/plan mode.
    """

    name: str
    args: list[str]
    background: bool = False
    from_step: str | None = None
    from_pipeline: str | None = None
    from_job: str | None = None
    from_topic: str | None = None
    replay_after_id: int = 0
    note: str | None = None
    display_name: str | None = None
    variable_expansions: tuple[str, ...] = ()
    expanded_text: str | None = None
    plan_only: bool = False
    approved: bool = False


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A parsed command pipeline.

    This represents a full command expression, including pipe order and shared
    pipeline metadata.
    Constructed by: `parse_pipeline()` from REPL/CLI text.
    Used by: runner pipeline execution to process ordered command invocations
    with shared metadata such as background mode and display name.
    """

    commands: tuple[CommandInvocation, ...]
    background: bool = False
    display_name: str | None = None


def parse_invocation(
    text: str,
    varstore: VarStore | None = None,
    command_resolver: Callable[[str], str] | None = None,
    command_scope_resolver: Callable[[str], str] | None = None,
) -> CommandInvocation:
    """Parse one commandlet expression.

    This function strips Bywaf framework selectors such as
    `--from step=1 topic=host.found` before plugin argparse sees the remaining
    plugin-owned arguments.
    """
    commandlet = provisional_command_name(text)
    commandlet_for_selectors = commandlet
    if commandlet is not None and command_resolver is not None:
        commandlet_for_selectors = command_resolver(commandlet)

    # `name=` and `note=` are framework-level free-text selectors for most
    # commandlets, but a few commandlets own those words as their own arguments.
    # Peel them only when the commandlet has not reserved the selector.
    if commandlet_owns_text_selector(commandlet_for_selectors, "name"):
        display_name = None
    else:
        text, display_name = peel_final_text_selector(text, "name")
    if commandlet_owns_text_selector(commandlet_for_selectors, "note"):
        note = None
    else:
        text, note = peel_final_text_selector(text, "note")
    variable_expansions: tuple[str, ...] = ()
    if varstore is not None and commandlet is not None:
        # Resolve aliases before variable expansion so `$timeout` in a scoped
        # command uses the same commandlet variable namespace that execution
        # will snapshot later.
        variable_scope = command_scope_resolver(commandlet) if command_scope_resolver is not None else commandlet
        original_text = text
        text, variable_expansions = expand_variables_in_text(text, varstore, variable_scope)
        expanded_text = text if text != original_text else None
    else:
        expanded_text = None
    tokens = shlex.split(text)
    background = False
    if tokens:
        tokens, background = peel_background_marker(tokens)
    if not tokens:
        raise ValueError("empty command")
    name, *args = tokens
    args, selectors = peel_context_selectors(args)
    # Only plugin-owned args are left in `args`.  Framework selectors are stored
    # separately so runner/context code can route input events, apply policy
    # plan flags, attach notes, and audit variable expansion consistently.
    return CommandInvocation(
        name=name,
        args=args,
        background=background,
        from_step=selectors["from_step"],
        from_pipeline=selectors["from_pipeline"],
        from_job=selectors["from_job"],
        from_topic=selectors["from_topic"],
        note=note,
        display_name=display_name,
        variable_expansions=variable_expansions,
        expanded_text=expanded_text,
        plan_only=selectors["plan_only"] == "true",
        approved=selectors["approved"] == "true",
    )


def parse_pipeline(
    command_line: str,
    varstore: VarStore | None = None,
    command_resolver: Callable[[str], str] | None = None,
    command_scope_resolver: Callable[[str], str] | None = None,
) -> Pipeline:
    """Parse a full pipeline and detect foreground/background execution."""
    command_line, display_name = peel_pipeline_name_prefix(command_line)
    parts, background = split_pipeline_raw(command_line)
    if not parts:
        raise ValueError("empty pipeline")
    commands = list(
        parse_invocation(
            part,
            varstore=varstore,
            command_resolver=command_resolver,
            command_scope_resolver=command_scope_resolver,
        )
        for part in parts
    )
    if background and commands:
        # A trailing `&` applies to the whole pipeline.  Store it on the final
        # stage so Runner can classify the parsed pipeline as background while
        # preserving each commandlet's own argument list.
        commands[-1] = invocation_with_background(commands[-1])
    return Pipeline(tuple(commands), any(command.background for command in commands), display_name)


def invocation_with_background(invocation: CommandInvocation) -> CommandInvocation:
    """Return a copy of an invocation marked for background pipeline execution."""
    return CommandInvocation(
        invocation.name,
        invocation.args,
        background=True,
        from_step=invocation.from_step,
        from_pipeline=invocation.from_pipeline,
        from_job=invocation.from_job,
        from_topic=invocation.from_topic,
        replay_after_id=invocation.replay_after_id,
        note=invocation.note,
        display_name=invocation.display_name,
        variable_expansions=invocation.variable_expansions,
        expanded_text=invocation.expanded_text,
        plan_only=invocation.plan_only,
        approved=invocation.approved,
    )


def provisional_command_name(text: str) -> str | None:
    """Return the first command token before variable expansion."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    return tokens[0] if tokens else None
