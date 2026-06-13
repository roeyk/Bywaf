"""Shared state for REPL shell and resource helpers.

Provides ShellState, ResourceState, prompt rendering, and default shell-state
construction without making resource modules import shell orchestration.

Used by:
- repl.shell: maintain interactive state and prompt text.
- REPL resource, project, persistence, and script helpers: type shared state.
"""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import Protocol

from ..db import EventStore
from ..projects import ProjectPaths
from ..registry import PluginRegistry
from ..time_format import OPERATOR_TIMESTAMP_FORMAT
from .resource.specs import DEFAULT_HISTORY

if TYPE_CHECKING:
    from ..runner import Runner


DEFAULT_HISTORY_TS_FORMAT = OPERATOR_TIMESTAMP_FORMAT
HISTORY_TIMESTAMP_FORMAT_VAR = "history.timestamp-format"


@dataclass(slots=True)
class ShellState:
    """Mutable REPL-only state that should not live in the database.

    Constructed by: `new_shell_state()` for interactive shells.
    Used by: REPL dispatch, completion, request handling, history, and prompt
    rendering. Durable runtime state belongs in `EventStore`, not here.
    """

    prompt_pattern: str = "$Y$M$D $h:$m:$s $Z%F> "
    history_path: Path = field(default_factory=lambda: DEFAULT_HISTORY)
    session_history: list[str] = field(default_factory=list)
    handled_request_ids: set[int] = field(default_factory=set)
    framework_request_after_id: int = 0
    active_context: str | None = None
    completer: Any | None = None
    secret_values: dict[str, str] = field(default_factory=dict)

    def prompt(self) -> str:
        """Render the current prompt pattern for display by the REPL loop."""
        return render_prompt(self.prompt_pattern, active_context=self.active_context)


class ResourceState(Protocol):
    """Mutable shell state used by resource commands.

    Implemented by: `ShellState`.
    Consumed by: resource/history helpers that should not depend on the full
    interactive shell implementation.
    """

    history_path: Path
    session_history: list[str]
    completer: Any | None


def default_resource_state(runner: Runner) -> ResourceState:
    """Create default resource state for non-interactive resource helpers.

    Called by: resource commands that need history/completion state outside a
    live REPL shell.
    """
    return new_shell_state(runner)


def new_shell_state(runner: Runner) -> ShellState:
    """Create shell state that ignores historical framework requests.

    Called by: REPL startup and resource helpers.
    """
    project = runner.project if isinstance(runner.project, ProjectPaths) else None
    history_path = project.history if project is not None else DEFAULT_HISTORY
    return ShellState(
        # Framework requests published before the shell starts should not be
        # replayed as fresh UI prompts in this session.
        framework_request_after_id=runner.events.latest_event_id(),
        history_path=history_path,
    )


def render_prompt(pattern: str, *, active_context: str | None = None) -> str:
    """Render prompt placeholders using local process and host metadata.

    Called by: `ShellState.prompt()` and prompt preview tests.
    """
    user = os.getenv("USER", "")
    host_full = socket.gethostname()
    now = datetime.now().astimezone()
    provider, commandlet = prompt_scope_parts(active_context)
    focus = f" {active_context}" if active_context else ""
    # Placeholder table consumed by the replacement loop below. Both `%x` and
    # `$x` forms exist for operator convenience and shell-prompt familiarity.
    replacements = {
        "%u": user,
        "%h": host_full.split(".", 1)[0],
        "%H": host_full,
        "%m": platform.machine(),
        "%T": now.strftime("%H:%M:%S"),
        "%p": provider,
        "%c": commandlet,
        "%P": active_context or "",
        "%F": focus,
        "$u": user,
        "$Y": now.strftime("%Y"),
        "$M": now.strftime("%m"),
        "$D": now.strftime("%d"),
        "$h": now.strftime("%H"),
        "$m": now.strftime("%M"),
        "$s": now.strftime("%S"),
        "$Z": now.strftime("%Z"),
    }
    prompt = pattern
    for key, value in replacements.items():
        # Replacement order is stable because the table is literal and small;
        # placeholders intentionally do not support escaping or nesting.
        prompt = prompt.replace(key, value)
    return prompt


def prompt_scope_parts(active_context: str | None) -> tuple[str, str]:
    """Return provider and commandlet prompt fields for the current focus.

    Called by: `render_prompt()`.
    """
    if not active_context:
        return "", ""
    provider, separator, commandlet = active_context.rpartition("/")
    if not separator:
        return active_context, ""
    return provider, commandlet


def hydrate_persistent_secrets(db: EventStore, registry: PluginRegistry) -> None:
    """Load persisted DB secrets back into the registry secret/variable stores.

    Called by: REPL/application startup after registry construction.
    """
    for secret_ref, value in db.stored_secrets():
        # VarStore holds the secret reference, not the cleartext; SecretStore
        # keeps the cleartext available for commandlet execution.
        registry.secrets.remember(secret_ref, value)
        registry.varstore.set(secret_ref.name, secret_ref.ref)
