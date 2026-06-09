"""Selector parsing for the runtime `note` commandlet.

Used by: `note.Note.run()` to normalize add/show mode before note storage
helpers resolve runtime IDs.
"""

from __future__ import annotations

from bywaf.plugin import parse_kvs, require_one_selector

NOTE_SELECTOR_KEYS = {"step", "pipeline", "job", "file", "text"}
NOTE_SCOPE_KEYS = ("step", "pipeline", "job")


def parse_note_args(args: list[str]) -> tuple[str, dict[str, str]]:
    """Parse `note` command mode and selectors."""
    if args and args[0] == "add":
        return "add", parse_note_selectors(args[1:], allow_text=True)
    return "show", parse_note_selectors(args, allow_text=False)


def parse_note_selectors(args: list[str], *, allow_text: bool) -> dict[str, str]:
    """Parse `note` command selectors and optional final text."""
    text_keys = {"text"} if allow_text else set()
    selectors = parse_kvs(args, allowed_keys=NOTE_SELECTOR_KEYS, command="note", text_keys=text_keys)
    if "text" in selectors and not allow_text:
        raise ValueError("text= is only valid with note add")
    validate_note_selectors(selectors, allow_text=allow_text)
    return selectors


def validate_note_selectors(selectors: dict[str, str], *, allow_text: bool) -> None:
    """Validate note scope and text/file selector combinations."""
    require_one_selector(selectors, NOTE_SCOPE_KEYS, command="note")
    if allow_text and ("text" in selectors) == ("file" in selectors):
        raise ValueError("note add requires exactly one text= or file= selector")
