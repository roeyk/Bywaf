"""Variable expansion helpers for command parsing."""

from __future__ import annotations

from dataclasses import dataclass

from ...varstore import VarStore


@dataclass
class ExpansionScan:
    """Mutable state for one variable-expansion pass.

    Constructed by: `expand_variables_in_text()`.
    Used by: `consume_scan_char()` and the small quote/escape helpers below to
    keep the public expansion function from carrying a dense scanner ladder.
    """

    output: list[str]
    expanded: list[str]
    quote: str | None = None
    escaped: bool = False


def expand_variables_in_text(text: str, varstore: VarStore, commandlet: str) -> tuple[str, tuple[str, ...]]:
    """Expand `$variables` outside single quotes before shell tokenization.

    Expansion happens before `shlex.split()` so variables can provide multiple
    words when the operator intends that.  Single quotes suppress expansion,
    while double quotes allow expansion with escaping suitable for the quoted
    context.
    """
    scan = ExpansionScan([], [])
    index = 0
    while index < len(text):
        index = consume_scan_char(text, index, scan, varstore, commandlet)
    return "".join(scan.output), tuple(dict.fromkeys(scan.expanded))


def consume_scan_char(text: str, index: int, scan: ExpansionScan, varstore: VarStore, commandlet: str) -> int:
    """Consume one character or variable reference from an expansion scan.

    Called by: `expand_variables_in_text()`.  The branch order mirrors shell
    quoting precedence: escaped characters first, single-quoted literal mode
    before double-quote toggling, and `$name` expansion only in unquoted or
    double-quoted text.
    """
    char = text[index]
    if scan.escaped:
        return consume_escaped_char(char, index, scan)
    if char == "\\":
        return begin_escape(char, index, scan)
    if scan.quote == "'":
        return consume_single_quoted_char(char, index, scan)
    if char == '"':
        return toggle_double_quote(char, index, scan)
    if char == "'":
        return begin_single_quote(char, index, scan)
    if char == "$":
        return consume_variable_reference(text, index, scan, varstore, commandlet)
    scan.output.append(char)
    return index + 1


def consume_escaped_char(char: str, index: int, scan: ExpansionScan) -> int:
    """Append a character that was escaped by the preceding backslash."""
    scan.output.append(char)
    scan.escaped = False
    return index + 1


def begin_escape(char: str, index: int, scan: ExpansionScan) -> int:
    """Copy a backslash and mark the next character as escaped."""
    scan.output.append(char)
    scan.escaped = True
    return index + 1


def consume_single_quoted_char(char: str, index: int, scan: ExpansionScan) -> int:
    """Copy literal text while inside single quotes."""
    scan.output.append(char)
    if char == "'":
        scan.quote = None
    return index + 1


def toggle_double_quote(char: str, index: int, scan: ExpansionScan) -> int:
    """Copy a double quote and enter or leave double-quoted mode."""
    scan.output.append(char)
    scan.quote = None if scan.quote == '"' else '"'
    return index + 1


def begin_single_quote(char: str, index: int, scan: ExpansionScan) -> int:
    """Copy a single quote and enter literal single-quoted mode."""
    scan.output.append(char)
    scan.quote = "'"
    return index + 1


def consume_variable_reference(
    text: str,
    index: int,
    scan: ExpansionScan,
    varstore: VarStore,
    commandlet: str,
) -> int:
    """Expand a `$name` or `${name}` reference, or copy `$` literally.

    Resolved variable names are retained for command-run audit events.  That is
    why this helper records both the replacement text and the fully resolved
    variable key returned by `resolve_variable_reference()`.
    """
    parsed = parse_variable_reference(text, index)
    if parsed is None:
        scan.output.append(text[index])
        return index + 1
    name, end = parsed
    value, resolved_name = resolve_variable_reference(varstore, commandlet, name)
    replacement = escape_double_quoted_value(value) if scan.quote == '"' else value
    scan.output.append(replacement)
    scan.expanded.append(resolved_name)
    return end


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
