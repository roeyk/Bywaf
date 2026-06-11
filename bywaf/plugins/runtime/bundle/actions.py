"""Action handlers and completion helpers for the runtime `bundle` command."""

from __future__ import annotations

import getpass
import hashlib
import json
from pathlib import Path
from typing import Any

from bywaf.keyring import sign_bytes, verify_bytes
from bywaf.plugin import CommandContext, CompletionContext, CompletionSpec
from bywaf.plugins.runtime.bundle.content import bundle_manifest, resolve_bundle_content
from bywaf.plugins.runtime.bundle.model import (
    BUNDLE_CONTENT_KINDS,
    canonical_json,
    first_content_kind,
    parse_bundle_selectors,
    require_selector,
)
from bywaf.plugins.runtime.bundle.state import all_bundles, bundle_by_name, require_bundle
from bywaf.utils import complete_path

BundleHandler = Any


def bundle_action_handlers() -> dict[str, BundleHandler]:
    """Return bundle action handlers keyed by action.

    Called by: `BundleCommand.run()`, which uses this dispatch table instead of
    an `if`/`elif` action ladder.
    """
    return {
        "add": add_bundle_item,
        "create": create_bundle,
        "export": export_bundle,
        "list": list_bundles,
        "seal": seal_bundle,
        "show": show_bundle,
        "verify": verify_bundle,
    }


def bundle_completion_selectors(action: str, prefix: str) -> list[str]:
    """Return selector candidates for a bundle action."""
    candidates = {
        "create": ["name="],
        "add": ["name=", *BUNDLE_CONTENT_KINDS, "topic=", "step=", "pipeline=", "job=", "serial=", "since=", "until=", "commandlet="],
        "seal": ["name=", "--sign", "key="],
        "verify": ["name="],
        "export": ["name=", "file="],
        "show": ["name="],
        "list": [],
    }.get(action, [])
    return [candidate for candidate in candidates if candidate.startswith(prefix)]


def completion_values(context: CompletionContext, kind: str, prefix: str) -> list[str]:
    """Use the framework completer for dynamic values when available."""
    completer = context.metadata.get("completer")
    if completer is not None:
        return [value for value in completer.complete_by_spec(CompletionSpec(kind), prefix) if value.startswith(prefix)]
    if kind == "bundle":
        try:
            events = context.event_store("bundle completion")
        except ValueError:
            return []
        return [
            str(event.payload["name"])
            for event in events.events_matching(topic="bundle.created", limit=100000)
            if str(event.payload.get("name", "")).startswith(prefix)
        ]
    return []


def complete_bundle_action(context: CompletionContext, args: list[str], prefix: str, actions: tuple[str, ...]) -> list[str]:
    """Complete bundle actions, selectors, file paths, and signing keys."""
    if not args:
        return list(actions)
    if len(args) == 1 and args[0] not in actions:
        return [action for action in actions if action.startswith(prefix)]
    if prefix.startswith("file="):
        return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
    if prefix.startswith("key="):
        value_prefix = prefix.removeprefix("key=")
        return [f"key={name}" for name in completion_values(context, "key.signing", value_prefix)]
    if prefix.startswith("name="):
        value_prefix = prefix.removeprefix("name=")
        return [f"name={name}" for name in completion_values(context, "bundle", value_prefix)]
    return bundle_completion_selectors(args[0], prefix)


def create_bundle(context: CommandContext, tokens: list[str]) -> None:
    """Create a named bundle record."""
    selectors = parse_bundle_selectors(tokens)
    name = require_selector(selectors, "name")
    if bundle_by_name(context, name) is not None:
        raise ValueError(f"bundle already exists: {name}")
    bundle_id = f"bundle-{hashlib.sha256(name.encode()).hexdigest()[:16]}"
    event = context.events.publish(
        "bundle.created",
        {"name": name, "bundle_id": bundle_id},
    )
    context.output(f"created bundle name={name} bundle_id={bundle_id} event={event.id}")


def add_bundle_item(context: CommandContext, tokens: list[str]) -> None:
    """Add an audit/artifact selector to a bundle."""
    if not tokens:
        raise ValueError("usage: bundle add name=<bundle> <audit|evidence|reports> [selectors]")
    selectors = parse_bundle_selectors(tokens)
    name = require_selector(selectors, "name")
    bundle = require_bundle(context, name)
    if bundle.sealed is not None:
        raise ValueError(f"bundle is sealed: {name}; create a new bundle for additional material")
    kind = first_content_kind(tokens)
    if kind is None:
        raise ValueError("bundle add requires audit, evidence, or reports")
    item_selectors = {key: value for key, value in selectors.items() if key != "name"}
    # Store selectors, not copied records. Bundles stay as durable saved scopes
    # until export/seal time, when the selectors are resolved into concrete
    # audit events and artifacts.
    count = len(resolve_bundle_content(context, kind, item_selectors)["records"])
    event = context.events.publish(
        "bundle.item.added",
        {
            "name": name,
            "kind": kind,
            "selectors": item_selectors,
            "matched": count,
        },
    )
    context.output(f"added bundle name={name} kind={kind} matched={count} event={event.id}")


def seal_bundle(context: CommandContext, tokens: list[str]) -> None:
    """Seal and optionally sign a bundle manifest."""
    selectors = parse_bundle_selectors(tokens)
    name = require_selector(selectors, "name")
    key = selectors.get("key")
    if "--sign" in tokens and key is None:
        raise ValueError("bundle seal --sign requires key=")
    bundle = require_bundle(context, name)
    manifest = bundle_manifest(context, bundle, include_bodies=False)
    canonical = canonical_json(manifest)
    # Sealing hashes the metadata manifest without artifact bodies. Export can
    # include bodies later, but the seal proves the selected evidence set.
    digest = hashlib.sha256(canonical).hexdigest()
    payload: dict[str, Any] = {
        "name": name,
        "bundle_id": bundle.bundle_id,
        "sha256": digest,
        "items": len(bundle.items),
    }
    if key is not None:
        passphrase = getpass.getpass(f"Passphrase for key {key}: ")
        payload["signature"] = sign_bytes(key, canonical, passphrase)
    event = context.events.publish("bundle.sealed", payload)
    context.output(f"sealed bundle name={name} sha256={digest} event={event.id}")


def verify_bundle(context: CommandContext, tokens: list[str]) -> None:
    """Verify a bundle hash and signature against current bundle contents."""
    selectors = parse_bundle_selectors(tokens)
    name = require_selector(selectors, "name")
    bundle = require_bundle(context, name)
    if bundle.sealed is None:
        raise ValueError(f"bundle is not sealed: {name}")
    manifest = bundle_manifest(context, bundle, include_bodies=False)
    canonical = canonical_json(manifest)
    digest = hashlib.sha256(canonical).hexdigest()
    expected = str(bundle.sealed.get("sha256", ""))
    if digest != expected:
        context.output(f"failed bundle name={name} sha256={digest} expected={expected}")
        return
    signature = bundle.sealed.get("signature")
    if isinstance(signature, dict):
        key = str(signature["key"])
        ok = verify_bytes(key, canonical, str(signature["signature"]))
        context.output(f"{'ok' if ok else 'failed'} bundle name={name} sha256={digest} signature_key={key}")
        return
    context.output(f"ok bundle name={name} sha256={digest}")


def export_bundle(context: CommandContext, tokens: list[str]) -> None:
    """Write a bundle manifest and selected content to a JSON file."""
    selectors = parse_bundle_selectors(tokens)
    name = require_selector(selectors, "name")
    file_name = require_selector(selectors, "file")
    bundle = require_bundle(context, name)
    manifest = bundle_manifest(context, bundle, include_bodies=True)
    path = Path(file_name).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(manifest) + b"\n")
    context.events.publish(
        "bundle.exported",
        {
            "name": name,
            "bundle_id": bundle.bundle_id,
            "file": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        },
    )
    context.output(f"exported bundle name={name} file={path}")


def list_bundles(context: CommandContext, tokens: list[str]) -> None:
    """List known bundles."""
    if tokens:
        raise ValueError("bundle list takes no selectors")
    bundles = sorted(all_bundles(context).values(), key=lambda bundle: bundle.name)
    if not bundles:
        context.output("no bundles")
        return
    for bundle in bundles:
        sealed = "sealed" if bundle.sealed else "open"
        context.output(f"name={bundle.name} bundle_id={bundle.bundle_id} items={len(bundle.items)} status={sealed}")


def show_bundle(context: CommandContext, tokens: list[str]) -> None:
    """Show one bundle."""
    selectors = parse_bundle_selectors(tokens)
    bundle = require_bundle(context, require_selector(selectors, "name"))
    context.output(json.dumps(bundle_manifest(context, bundle, include_bodies=False), sort_keys=True, indent=2))
