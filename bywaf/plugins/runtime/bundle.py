"""Runtime bundle commandlet.

Provides a bundled plugin implementation and CommandSpec metadata. Groups runtime entities and artifacts into named bundles.

Used by:
- PluginRegistry discovery: loads this module as a commandlet provider.
- runner and REPL: execute it through normal commandlet dispatch."""


from __future__ import annotations

import base64
import getpass
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bywaf.artifacts import Artifact, artifact_store_for_event_store
from bywaf.events import Event
from bywaf.keyring import sign_bytes, verify_bytes
from bywaf.plugin import (
    CommandContext,
    Commandlet,
    CommandletBase,
    CompletionContext,
    CompletionSpec,
    argument,
    commandlet,
)
from bywaf.plugins.runtime import audit as audit_plugin
from bywaf.plugins.runtime.artifact import artifact_event_payload
from bywaf.utils import complete_path

BUNDLE_ACTIONS = ("add", "create", "export", "list", "seal", "show", "verify")
BUNDLE_CONTENT_KINDS = ("audit", "evidence", "reports")


@dataclass(frozen=True, slots=True)
class Bundle:
    """Reconstructed bundle state from durable audit events."""

    name: str
    bundle_id: str
    created_at: str
    items: tuple[dict[str, Any], ...]
    sealed: dict[str, Any] | None = None


@commandlet(
    name="bundle",
    description="Create, populate, sign, verify, and export evidence bundles.",
    usage="bundle <create|add|list|show|seal|verify|export> name=<bundle> [audit|evidence|reports] [file=<path>]",
    examples=(
        "bundle create name=client-a",
        "bundle add name=client-a audit since=20260501 until=20260519",
        "bundle add name=client-a evidence commandlet=nikto,webfin",
        "bundle seal name=client-a --sign key=firm-evidence",
        "bundle verify name=client-a",
        "bundle export name=client-a file=client-a.bundle.json",
    ),
    emits=("bundle.created", "bundle.item.added", "bundle.sealed", "bundle.exported"),
    capabilities=(
        "artifact.read",
        "db.read:bundle.created",
        "db.read:bundle.item.added",
        "db.read:bundle.sealed",
        "db.write:bundle.created",
        "db.write:bundle.item.added",
        "db.write:bundle.sealed",
        "db.write:bundle.exported",
        "filesystem.write",
        "framework.console.output",
    ),
)
@argument("action", "bundle action", completion=CompletionSpec("choice", BUNDLE_ACTIONS))
class BundleCommand(CommandletBase):
    """Manage auditable evidence bundles."""

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Dispatch one bundle action."""
        del input_events
        if not args:
            raise ValueError("bundle requires an action")
        action, *tokens = args
        handlers = bundle_action_handlers()
        if action not in handlers:
            raise ValueError(f"unknown bundle action: {action}")
        handlers[action](context, tokens)
        return ()

    def complete(self, context: CompletionContext, args: list[str], prefix: str) -> list[str]:
        """Complete bundle actions, content kinds, file paths, and key names."""
        if not args:
            return list(BUNDLE_ACTIONS)
        if len(args) == 1 and args[0] not in BUNDLE_ACTIONS:
            return [action for action in BUNDLE_ACTIONS if action.startswith(prefix)]
        if prefix.startswith("file="):
            return [f"file={candidate}" for candidate in complete_path(prefix.removeprefix("file="))]
        if prefix.startswith("key="):
            value_prefix = prefix.removeprefix("key=")
            return [f"key={name}" for name in completion_values(context, "key.signing", value_prefix)]
        if prefix.startswith("name="):
            value_prefix = prefix.removeprefix("name=")
            return [f"name={name}" for name in completion_values(context, "bundle", value_prefix)]
        return bundle_completion_selectors(args[0], prefix)


BundleHandler = Any


def bundle_action_handlers() -> dict[str, BundleHandler]:
    """Return bundle action handlers keyed by action."""
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
    if kind == "bundle" and context.db is not None:
        return [
            str(event.payload["name"])
            for event in context.db.events_matching(topic="bundle.created", limit=100000)
            if str(event.payload.get("name", "")).startswith(prefix)
        ]
    return []


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


def parse_bundle_selectors(tokens: list[str]) -> dict[str, str]:
    """Parse bundle key=value selectors and flags."""
    selectors: dict[str, str] = {}
    for token in tokens:
        if token in {"--sign", *BUNDLE_CONTENT_KINDS}:
            continue
        if "=" not in token:
            raise ValueError(f"invalid bundle selector: {token}")
        key, value = token.split("=", 1)
        if not value:
            raise ValueError(f"bundle selector {key}= requires a value")
        selectors[key] = value
    return selectors


def require_selector(selectors: dict[str, str], name: str) -> str:
    """Return a required selector."""
    try:
        return selectors[name]
    except KeyError as exc:
        raise ValueError(f"bundle {name}= is required") from exc


def first_content_kind(tokens: list[str]) -> str | None:
    """Return the first content kind token."""
    for token in tokens:
        if token in BUNDLE_CONTENT_KINDS:
            return token
    return None


def all_bundles(context: CommandContext) -> dict[str, Bundle]:
    """Reconstruct bundles from durable events."""
    events = context.event_store("bundle").events_matching(limit=100000)
    bundles: dict[str, Bundle] = {}
    item_map: dict[str, list[dict[str, Any]]] = {}
    sealed: dict[str, dict[str, Any]] = {}
    for event in events:
        # Bundle state is event-sourced so sealed bundles remain auditable and
        # can be reconstructed even after process restart.
        name = event.payload.get("name")
        if not isinstance(name, str):
            continue
        if event.topic == "bundle.created":
            bundles[name] = Bundle(
                name=name,
                bundle_id=str(event.payload.get("bundle_id", "")),
                created_at=event.created_at.isoformat(),
                items=(),
            )
        elif event.topic == "bundle.item.added":
            item_map.setdefault(name, []).append(dict(event.payload))
        elif event.topic == "bundle.sealed":
            sealed[name] = dict(event.payload)
    return {
        name: Bundle(
            name=bundle.name,
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            items=tuple(item_map.get(name, [])),
            sealed=sealed.get(name),
        )
        for name, bundle in bundles.items()
    }


def bundle_by_name(context: CommandContext, name: str) -> Bundle | None:
    """Return a bundle by name if it exists."""
    return all_bundles(context).get(name)


def require_bundle(context: CommandContext, name: str) -> Bundle:
    """Return a bundle or raise a user-facing error."""
    bundle = bundle_by_name(context, name)
    if bundle is None:
        raise ValueError(f"unknown bundle: {name}")
    return bundle


def bundle_manifest(context: CommandContext, bundle: Bundle, *, include_bodies: bool) -> dict[str, Any]:
    """Build a deterministic bundle manifest."""
    items: list[dict[str, Any]] = []
    for item in bundle.items:
        # Resolve each saved selector just-in-time. This keeps create/add cheap
        # while allowing seal/export to operate on the current project DB.
        kind = str(item["kind"])
        selectors = dict(item.get("selectors", {}))
        items.append(resolve_bundle_content(context, kind, selectors, include_bodies=include_bodies))
    return {
        "format": "bywaf.bundle.v1",
        "name": bundle.name,
        "bundle_id": bundle.bundle_id,
        "created_at": bundle.created_at,
        "items": items,
    }


def resolve_bundle_content(
    context: CommandContext,
    kind: str,
    selectors: dict[str, str],
    *,
    include_bodies: bool = False,
) -> dict[str, Any]:
    """Resolve one bundle item into concrete event or artifact records."""
    if kind == "audit":
        events = audit_plugin.selected_events(context, selectors, limit=100000)
        return {
            "kind": kind,
            "selectors": selectors,
            "records": [audit_plugin.event_record(event) for event in events],
        }
    if kind in {"evidence", "reports"}:
        artifacts = selected_artifacts(context, selectors)
        return {
            "kind": kind,
            "selectors": selectors,
            "records": [artifact_record(artifact, include_body=include_bodies) for artifact in artifacts],
        }
    raise ValueError(f"unsupported bundle content kind: {kind}")


def selected_artifacts(context: CommandContext, selectors: dict[str, str]) -> list[Artifact]:
    """Return artifacts selected for a bundle item."""
    store = artifact_store_for_event_store(context.require_db("bundle"))
    artifacts = store.list(
        job_id=selectors.get("job"),
        pipeline_id=resolve_pipeline_selector(context, selectors.get("pipeline")),
        command_run_id=resolve_run_selector(context, selectors.get("step")),
    )
    if "serial" in selectors:
        wanted = selectors["serial"]
        artifacts = [
            artifact
            for artifact in artifacts
            if wanted in {artifact.artifact_id, artifact.pipeline_id, artifact.command_run_id, artifact.job_id}
        ]
    if "commandlet" in selectors:
        wanted = set(split_csv(selectors["commandlet"]))
        artifacts = [artifact for artifact in artifacts if artifact.commandlet in wanted]
    if "since" in selectors or "until" in selectors:
        from bywaf.plugins.runtime.artifact import filter_artifact_time_window

        artifacts = filter_artifact_time_window(
            artifacts,
            since=selectors.get("since"),
            until=selectors.get("until"),
        )
    return artifacts


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve local step id selectors to durable serials."""
    return context.runtime_store("bundle").resolve_run_serial(value) if value is not None else None


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve local pipeline id selectors to durable serials."""
    return context.runtime_store("bundle").resolve_pipeline_serial(value) if value is not None else None


def artifact_record(artifact: Artifact, *, include_body: bool) -> dict[str, Any]:
    """Return bundle-safe artifact metadata, optionally including body bytes."""
    record = artifact_event_payload(artifact)
    if include_body:
        record["body_base64"] = base64.b64encode(artifact.body).decode("ascii")
    return record


def split_csv(value: str) -> list[str]:
    """Split a comma-separated selector value."""
    return [item.strip() for item in value.split(",") if item.strip()]


def canonical_json(value: Any) -> bytes:
    """Return deterministic JSON bytes for hashing/signing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def plugin() -> Commandlet:
    """Return the commandlet instance discovered by the plugin registry."""
    return BundleCommand()
