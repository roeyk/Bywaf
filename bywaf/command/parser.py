"""Command-line parsing helpers for commandlet execution.

Provides parsing for pipelines, framework selector flags, at-file expansion,
variable expansion, and commandlet argument normalization.

Used by:
- runner: turns REPL/CLI command text into executable commandlet invocations.
- resource script loading: parses commands loaded from script files."""


from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass

from ..varstore import VarStore
from .parser_variables import expand_variables_in_text as expand_variables_in_text
from .pipeline_syntax import (
    find_pipeline_name_colon as find_pipeline_name_colon,
    is_quoted_position as is_quoted_position,
    normalize_final_text,
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


COMMANDLET_TEXT_SELECTORS = {
    "artifact": frozenset({"name", "note"}),
    "bundle": frozenset({"name"}),
    "key": frozenset({"name"}),
    "report": frozenset({"name", "note"}),
    "search": frozenset({"name", "note"}),
}


def commandlet_owns_text_selector(commandlet: str | None, key: str) -> bool:
    """Return whether a commandlet owns a selector that would otherwise be framework text.

    This prevents the framework parser from consuming valid plugin arguments
    such as `report defer 1 note=...` before the commandlet has a chance to
    parse them.
    """
    if commandlet is None:
        return False
    return key in COMMANDLET_TEXT_SELECTORS.get(commandlet, frozenset())


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


def peel_background_marker(tokens: list[str]) -> tuple[list[str], bool]:
    """Remove a trailing shell-style `&` marker from a token list."""
    last = tokens[-1]
    if last == "&":
        return tokens[:-1], True
    if last.endswith("&"):
        stripped = last[:-1]
        if stripped:
            return [*tokens[:-1], stripped], True
        return tokens[:-1], True
    return tokens, False


def peel_final_text_selector(text: str, key: str) -> tuple[str, str | None]:
    """Remove a framework-owned final text selector from raw stage text.

    The selector is parsed before `shlex.split` so a final unquoted note can
    consume the rest of the command stage:

    `hostscanner targets note=client approved`
    """
    index = find_unquoted_text_selector(text, key)
    if index is None:
        return text, None
    value = normalize_final_text(text[index + len(key) + 1:])
    if not value:
        raise ValueError(f"{key}= requires a value")
    return text[:index].rstrip(), value


def find_unquoted_text_selector(text: str, key: str) -> int | None:
    """Return the index of a token-boundary text selector outside shell quotes."""
    quote: str | None = None
    escaped = False
    needle = f"{key}="
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if text.startswith(needle, index) and (index == 0 or text[index - 1].isspace()):
            return index
    return None


def provisional_command_name(text: str) -> str | None:
    """Return the first command token before variable expansion."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    return tokens[0] if tokens else None


def peel_context_selectors(args: list[str]) -> tuple[list[str], dict[str, str | None]]:
    """Remove framework-owned selector flags from plugin arguments."""
    selectors: dict[str, str | None] = {
        "from_step": None,
        "from_pipeline": None,
        "from_job": None,
        "from_topic": None,
        "plan_only": "false",
        "approved": "false",
    }
    cleaned: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--from":
            index += 1
            replay_selectors: set[str] = set()
            while index < len(args):
                key, value = context_selector_assignment(args[index])
                if key is None:
                    break
                selectors[key] = value
                replay_selectors.add(key)
                index += 1
            if not replay_selectors:
                raise ValueError("--from requires job=, pipeline=, or step=")
            if replay_selectors.isdisjoint({"from_job", "from_pipeline", "from_step"}):
                raise ValueError("--from requires job=, pipeline=, or step=; topic= only narrows replay input")
            continue
        selector_value = CONTEXT_SELECTOR_BOOL_FLAGS.get(token)
        if selector_value is not None:
            key, value = selector_value
            selectors[key] = value
            index += 1
            continue
        cleaned.append(token)
        index += 1
    return cleaned, selectors


CONTEXT_SELECTOR_KEYS = {
    "pipeline": "from_pipeline",
    "job": "from_job",
    "step": "from_step",
    "topic": "from_topic",
}
CONTEXT_SELECTOR_BOOL_FLAGS = {
    "--test": ("plan_only", "true"),
    "--yes": ("approved", "true"),
}


def context_selector_assignment(token: str) -> tuple[str | None, str | None]:
    """Return a framework replay selector assignment, if the token is one."""
    key, separator, value = token.partition("=")
    if not separator:
        return None, None
    selector = CONTEXT_SELECTOR_KEYS.get(key)
    if selector is None:
        return None, None
    if not value:
        raise ValueError(f"--from {key}= requires a value")
    return selector, value
