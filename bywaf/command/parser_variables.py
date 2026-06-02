"""Variable expansion helpers for command parsing."""

from __future__ import annotations

from ..varstore import VarStore


def expand_variables_in_text(text: str, varstore: VarStore, commandlet: str) -> tuple[str, tuple[str, ...]]:
    """Expand `$variables` outside single quotes before shell tokenization.

    Expansion happens before `shlex.split()` so variables can provide multiple
    words when the operator intends that.  Single quotes suppress expansion,
    while double quotes allow expansion with escaping suitable for the quoted
    context.
    """
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
        # Store the resolved variable name for audit.  This lets a step record
        # that `$target` expanded from, for example,
        # `http/repo_exposure/git_expose_check.target`.
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
