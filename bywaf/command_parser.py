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

from .varstore import VarStore


@dataclass(frozen=True, slots=True)
class CommandInvocation:
    """Parsed commandlet invocation plus framework-owned execution selectors."""

    name: str
    args: list[str]
    background: bool = False
    from_step: str | None = None
    from_pipeline: str | None = None
    from_topic: str | None = None
    replay_after_id: int = 0
    note: str | None = None
    display_name: str | None = None
    variable_expansions: tuple[str, ...] = ()
    plan_only: bool = False
    approved: bool = False


@dataclass(frozen=True, slots=True)
class Pipeline:
    """A sequence of commandlets connected by pipe syntax."""

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

    This function strips Bywaf framework selectors such as `--from-step` before
    plugin argparse sees the remaining plugin-owned arguments.
    """
    commandlet = provisional_command_name(text)
    commandlet_for_selectors = commandlet
    if commandlet is not None and command_resolver is not None:
        commandlet_for_selectors = command_resolver(commandlet)
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
        variable_scope = command_scope_resolver(commandlet) if command_scope_resolver is not None else commandlet
        text, variable_expansions = expand_variables_in_text(text, varstore, variable_scope)
    tokens = shlex.split(text)
    background = False
    if tokens:
        tokens, background = peel_background_marker(tokens)
    if not tokens:
        raise ValueError("empty command")
    name, *args = tokens
    args, selectors = peel_context_selectors(args)
    return CommandInvocation(
        name=name,
        args=args,
        background=background,
        from_step=selectors["from_step"],
        from_pipeline=selectors["from_pipeline"],
        from_topic=selectors["from_topic"],
        note=note,
        display_name=display_name,
        variable_expansions=variable_expansions,
        plan_only=selectors["plan_only"] == "true",
        approved=selectors["approved"] == "true",
    )


COMMANDLET_TEXT_SELECTORS = {
    "artifact": frozenset({"name", "note"}),
    "bundle": frozenset({"name"}),
    "key": frozenset({"name"}),
    "report": frozenset({"note"}),
    "search": frozenset({"name", "note"}),
}


def commandlet_owns_text_selector(commandlet: str | None, key: str) -> bool:
    """Return whether a commandlet owns a selector that would otherwise be framework text."""
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
        last = commands[-1]
        commands[-1] = CommandInvocation(
            last.name,
            last.args,
            background=True,
            from_step=last.from_step,
            from_pipeline=last.from_pipeline,
            from_topic=last.from_topic,
            replay_after_id=last.replay_after_id,
            note=last.note,
            display_name=last.display_name,
            variable_expansions=last.variable_expansions,
            plan_only=last.plan_only,
            approved=last.approved,
        )
    return Pipeline(tuple(commands), any(command.background for command in commands), display_name)


def split_pipeline_raw(command_line: str) -> tuple[list[str], bool]:
    """Split a pipeline without changing quote context inside each stage."""
    command_line, background = peel_pipeline_background(command_line)
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
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
        if char == "|":
            part = command_line[start:index].strip()
            if part:
                parts.append(part)
            start = index + 1
    final = command_line[start:].strip()
    if final:
        parts.append(final)
    return parts, background


def peel_pipeline_background(command_line: str) -> tuple[str, bool]:
    """Remove a trailing standalone `&` from a full pipeline expression."""
    stripped = command_line.rstrip()
    if not stripped.endswith("&"):
        return command_line, False
    amp_index = len(stripped) - 1
    if amp_index == 0 or not stripped[amp_index - 1].isspace():
        return command_line, False
    if is_quoted_position(stripped, amp_index):
        return command_line, False
    return stripped[:amp_index].rstrip(), True


def is_quoted_position(text: str, position: int) -> bool:
    """Return whether one character index is inside shell-style quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if index == position:
            return quote is not None
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
    return False


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


def normalize_final_text(raw_value: str) -> str:
    """Return selector text with shell quotes removed when possible."""
    stripped = raw_value.strip()
    if not stripped:
        return ""
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return stripped
    return " ".join(tokens)


def provisional_command_name(text: str) -> str | None:
    """Return the first command token before variable expansion."""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    return tokens[0] if tokens else None


def expand_variables_in_text(text: str, varstore: VarStore, commandlet: str) -> tuple[str, tuple[str, ...]]:
    """Expand `$variables` outside single quotes before shell tokenization."""
    output: list[str] = []
    expanded: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            output.append(char)
            escaped = True
            index += 1
            continue
        if quote == "'":
            output.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == '"':
            output.append(char)
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char == "'":
            output.append(char)
            quote = "'"
            index += 1
            continue
        if char != "$":
            output.append(char)
            index += 1
            continue
        parsed = parse_variable_reference(text, index)
        if parsed is None:
            output.append(char)
            index += 1
            continue
        name, end = parsed
        value, resolved_name = resolve_variable_reference(varstore, commandlet, name)
        replacement = escape_double_quoted_value(value) if quote == '"' else value
        output.append(replacement)
        expanded.append(resolved_name)
        index = end
    return "".join(output), tuple(dict.fromkeys(expanded))


def parse_variable_reference(text: str, dollar_index: int) -> tuple[str, int] | None:
    """Return a variable name and end index for `$name` or `${name}`."""
    start = dollar_index + 1
    if start >= len(text):
        return None
    if text[start] == "{":
        end = text.find("}", start + 1)
        if end == -1:
            raise ValueError("unterminated variable reference")
        name = text[start + 1:end]
        if not name:
            raise ValueError("empty variable reference")
        return name, end + 1
    if not (text[start].isalpha() or text[start] == "_"):
        return None
    end = start + 1
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return text[start:end], end


def resolve_variable_reference(varstore: VarStore, commandlet: str, name: str) -> tuple[str, str]:
    """Resolve a `$variable` against exact, commandlet, then global scopes."""
    candidates = [name]
    if "/" not in name and "." not in name:
        candidates.extend((f"{commandlet}.{name}", f"global.{name}"))
    for candidate in candidates:
        value = varstore.get(candidate)
        if value is not None:
            return value, candidate
    raise ValueError(f"unknown variable: ${name}")


def escape_double_quoted_value(value: str) -> str:
    """Escape replacement text that is inserted inside double quotes."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def peel_pipeline_name_prefix(command_line: str) -> tuple[str, str | None]:
    """Remove a leading `pipeline name: command` prefix when present."""
    index = find_pipeline_name_colon(command_line)
    if index is None:
        return command_line, None
    display_name = normalize_final_text(command_line[:index])
    command = command_line[index + 1:].strip()
    if not display_name or not command:
        return command_line, None
    return command, display_name


def find_pipeline_name_colon(command_line: str) -> int | None:
    """Find a top-level naming colon followed by whitespace before any pipe."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(command_line):
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
        if char == "|":
            return None
        if char == ":" and index + 1 < len(command_line) and command_line[index + 1].isspace():
            return index
    return None


def peel_context_selectors(args: list[str]) -> tuple[list[str], dict[str, str | None]]:
    """Remove framework-owned selector flags from plugin arguments."""
    selectors: dict[str, str | None] = {
        "from_step": None,
        "from_pipeline": None,
        "from_topic": None,
        "plan_only": "false",
        "approved": "false",
    }
    cleaned: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        selector_key = CONTEXT_SELECTOR_VALUE_FLAGS.get(token)
        if selector_key is not None:
            selectors[selector_key] = require_selector_value(args, index, token)
            index += 2
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


CONTEXT_SELECTOR_VALUE_FLAGS = {
    "--from": "from_step",
    "--from-pipeline": "from_pipeline",
    "--from-step": "from_step",
    "--from-topic": "from_topic",
    "--pipeline": "from_pipeline",
    "--topic": "from_topic",
}
CONTEXT_SELECTOR_BOOL_FLAGS = {
    "--test": ("plan_only", "true"),
    "--yes": ("approved", "true"),
}


def require_selector_value(args: list[str], index: int, token: str) -> str:
    """Return the value after a selector flag or raise a friendly parse error."""
    try:
        return args[index + 1]
    except IndexError as exc:
        raise ValueError(f"{token} requires a value") from exc
