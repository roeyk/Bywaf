"""Runtime-backed completion providers.

Provides candidates sourced from key records, bundle events, and fixed built-in
selectors. Used by the completion engine when a CompletionSpec references
runtime state outside the plugin registry.

Used by:
- completion engine: fetch runtime-backed candidates on demand.
- REPL completion adapters: render candidates for prompt-toolkit/readline.
"""

from __future__ import annotations

from ..db import EventStore


def key_candidates(*, signing: bool = False, verify: bool = False) -> list[str]:
    """Return key names for completion without making cryptography mandatory."""
    try:
        # Completion should degrade gracefully on minimal installs where the
        # optional crypto stack or key files are unavailable.
        from ..keyring import load_key_records, signing_key_names, verification_key_names
    except Exception:
        return []
    try:
        if signing:
            return signing_key_names()
        if verify:
            return verification_key_names()
        return [record.name for record in load_key_records()]
    except Exception:
        return []


def bundle_candidates(db: EventStore | None) -> list[str]:
    """Return known bundle names for completion."""
    if db is None:
        return []
    try:
        # Bundles are event-sourced, so completion reads bundle.created events
        # instead of a separate mutable bundle table.
        return sorted(
            {
                str(event.payload["name"])
                for event in db.events_matching(topic="bundle.created", limit=100000)
                if "name" in event.payload
            }
        )
    except Exception:
        return []


def history_candidates(prefix: str) -> list[str]:
    """Complete timestamp-window selectors for the built-in history command."""
    selectors = ("since=", "until=")
    return [selector for selector in selectors if selector.startswith(prefix)]
