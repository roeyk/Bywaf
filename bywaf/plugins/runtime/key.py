"""Runtime key commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Manages signing and verification keys from inside Bywaf.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import getpass
from collections.abc import Callable, Iterable
from pathlib import Path

from bywaf.events import Event
from bywaf.keyring import (
    KeyRecord,
    export_public_key,
    generate_key,
    import_private_key,
    import_public_key,
    key_by_name,
    load_key_records,
    remove_key,
    test_key,
    verification_key_names,
)
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.runtime_display import render_table

KEY_ACTIONS = ("export", "generate", "import", "list", "remove", "show", "test")


@commandlet(
    name="key",
    description="Manage signing and verification keys.",
    usage="key <list|show|generate|import|export|remove|test> [options]",
    examples=(
        "key list",
        "key generate name=firm-evidence",
        "key show name=firm-evidence",
        "key import public file=reviewer.pub name=reviewer",
        "key export public name=firm-evidence file=firm-evidence.pub",
    ),
    emits=("key.generated", "key.imported", "key.removed", "key.tested"),
    capabilities=(
        "db.write:key.generated",
        "db.write:key.imported",
        "db.write:key.removed",
        "db.write:key.tested",
        "filesystem.read",
        "filesystem.write",
        "framework.console.output",
    ),
)
@argument("action", "key operation", completion=CompletionSpec("choice", KEY_ACTIONS))
class Key(CommandletBase):
    """Generate, import, inspect, and test signing/verification keys."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Dispatch one key-management action."""
        del input_events
        context.require_foreground("key management commands")
        if not args:
            raise ValueError("usage: key <list|show|generate|import|export|remove|test>")
        action = args[0]
        rest = args[1:]
        handler = KEY_ACTION_HANDLERS.get(action)
        if handler is None:
            raise ValueError(f"unknown key action: {action}")
        handler(context, rest)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete key actions, selectors, files, and key names."""
        del context
        if not args:
            return list(KEY_ACTIONS)
        if len(args) == 1 and not args[0].startswith("name="):
            return [action for action in KEY_ACTIONS if action.startswith(prefix)]
        action = args[0]
        if prefix.startswith("name="):
            value_prefix = prefix.split("=", 1)[1]
            return [f"name={name}" for name in key_names_for_action(action) if name.startswith(value_prefix)]
        if prefix.startswith("file="):
            from bywaf.utils import complete_path

            value_prefix = prefix.split("=", 1)[1]
            return [f"file={candidate}" for candidate in complete_path(value_prefix or ".")]
        if action == "import" and len(args) == 1:
            return ["private", "public"]
        return selector_candidates(action, prefix)


def list_keys(context: CommandContext) -> None:
    """Print known keys with computed signing state."""
    rows = [
        (
            record.name,
            record.scope,
            record.algorithm,
            record.fingerprint,
            record.signing_state,
            str(record.public_path or ""),
            str(record.private_path or ""),
        )
        for record in load_key_records()
    ]
    if not rows:
        context.output("no keys")
        return
    context.output(render_table(("NAME", "SCOPE", "ALG", "FINGERPRINT", "SIGNING", "PUBLIC", "PRIVATE"), rows))


def show_key(context: CommandContext, name: str) -> None:
    """Print metadata for one key."""
    record = key_by_name(name)
    context.output(format_key_record(record))


def generate_key_action(context: CommandContext, args: list[str]) -> None:
    """Generate a new encrypted private key and matching public key."""
    name = selector(args, "name", required=True)
    scope = selector(args, "scope") or "user"
    passphrase = prompt_new_passphrase(name)
    record = generate_key(name, passphrase, scope=scope)
    context.events.publish("key.generated", key_event_payload(record))
    context.output(f"generated key name={record.name} fingerprint={record.fingerprint} signing={record.signing_state}")


def import_key_action(context: CommandContext, args: list[str]) -> None:
    """Import private or public key material."""
    if not args or args[0] not in {"private", "public"}:
        raise ValueError("usage: key import <private|public> file=<path> name=<key> [scope=user|project]")
    kind = args[0]
    rest = args[1:]
    name = selector(rest, "name", required=True)
    file_name = selector(rest, "file", required=True)
    scope = selector(rest, "scope") or "user"
    if kind == "public":
        record = import_public_key(name, Path(file_name), scope=scope)
    else:
        existing_passphrase = prompt_optional_passphrase(f"Existing passphrase for private key {file_name} (blank if none): ")
        new_passphrase = prompt_new_passphrase(name)
        record = import_private_key(
            name,
            Path(file_name),
            scope=scope,
            existing_passphrase=existing_passphrase or None,
            new_passphrase=new_passphrase,
        )
    context.events.publish("key.imported", {**key_event_payload(record), "kind": kind})
    context.output(f"imported {kind} key name={record.name} fingerprint={record.fingerprint} signing={record.signing_state}")


def export_key_action(context: CommandContext, args: list[str]) -> None:
    """Export public key material."""
    if not args or args[0] != "public":
        raise ValueError("usage: key export public name=<key> file=<path>")
    name = selector(args[1:], "name", required=True)
    file_name = selector(args[1:], "file", required=True)
    record = export_public_key(name, Path(file_name))
    context.output(f"exported public key name={record.name} file={file_name}")


def remove_key_action(context: CommandContext, args: list[str]) -> None:
    """Remove key metadata, optionally deleting files."""
    name = selector(args, "name", required=True)
    delete_files = "--delete-files" in args
    record = remove_key(name, delete_files=delete_files)
    context.events.publish("key.removed", {**key_event_payload(record), "delete_files": delete_files})
    context.output(f"removed key name={record.name}")


def test_key_action(context: CommandContext, name: str) -> None:
    """Validate key metadata and private/public consistency."""
    record = key_by_name(name)
    passphrase = None
    if record.signing_state == "locked":
        passphrase = getpass.getpass(f"Passphrase for key {name}: ")
    state = test_key(name, passphrase)
    context.events.publish("key.tested", {**key_event_payload(record), "signing": state})
    context.output(f"key ok name={name} signing={state}")


KeyActionHandler = Callable[[CommandContext, list[str]], None]


def list_key_action(context: CommandContext, args: list[str]) -> None:
    """List key records."""
    del args
    list_keys(context)


def show_key_action(context: CommandContext, args: list[str]) -> None:
    """Show one key record."""
    show_key(context, selector(args, "name", required=True))


def test_key_selector_action(context: CommandContext, args: list[str]) -> None:
    """Run signing/verification self-test for one key."""
    test_key_action(context, selector(args, "name", required=True))


KEY_ACTION_HANDLERS: dict[str, KeyActionHandler] = {
    "export": export_key_action,
    "generate": generate_key_action,
    "import": import_key_action,
    "list": list_key_action,
    "remove": remove_key_action,
    "show": show_key_action,
    "test": test_key_selector_action,
}


def key_event_payload(record: KeyRecord) -> dict[str, str]:
    """Return audit-safe key metadata."""
    return {
        "name": record.name,
        "scope": record.scope,
        "algorithm": record.algorithm,
        "fingerprint": record.fingerprint,
        "signing": record.signing_state,
    }


def format_key_record(record: KeyRecord) -> str:
    """Format one key without revealing private material."""
    return "\n".join(
        [
            f"name={record.name}",
            f"scope={record.scope}",
            f"algorithm={record.algorithm}",
            f"fingerprint={record.fingerprint}",
            f"signing={record.signing_state}",
            f"public={record.public_path or ''}",
            f"private={'present' if record.private_path else 'absent'}",
        ]
    )


def selector(args: list[str], key: str, *, required: bool = False) -> str:
    """Return a key=value selector from arguments."""
    prefix = f"{key}="
    for arg in args:
        if arg.startswith(prefix):
            value = arg.split("=", 1)[1]
            if value:
                return value
    if required:
        raise ValueError(f"{key}= is required")
    return ""


def selector_candidates(action: str, prefix: str) -> list[str]:
    """Return selector candidates for a key action."""
    candidates = {
        "generate": ["name=", "scope=user", "scope=project"],
        "show": ["name="],
        "test": ["name="],
        "remove": ["name=", "--delete-files"],
        "import": ["private", "public", "file=", "name=", "scope=user", "scope=project"],
        "export": ["public", "name=", "file="],
        "list": [],
    }.get(action, [])
    return [candidate for candidate in candidates if candidate.startswith(prefix)]


def key_names_for_action(action: str) -> list[str]:
    """Return key-name completion candidates for one action."""
    if action == "test":
        return verification_key_names()
    return [record.name for record in load_key_records()]


def prompt_new_passphrase(name: str) -> str:
    """Prompt and confirm a new key passphrase."""
    first = getpass.getpass(f"New passphrase for key {name}: ")
    second = getpass.getpass(f"Confirm passphrase for key {name}: ")
    if first != second:
        raise ValueError("passphrases do not match")
    if not first:
        raise ValueError("private key passphrase cannot be empty")
    return first


def prompt_optional_passphrase(prompt: str) -> str:
    """Prompt for a passphrase that may be blank."""
    return getpass.getpass(prompt)


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return Key()
