"""Process audit redaction helpers for framework-mediated tool execution.

Used by: `plugin.process.ContextProcess` before publishing process request and
result events. These helpers keep secret detection/redaction separate from the
subprocess launch and streaming control flow.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ...secret.store import REDACTED_VALUE

if TYPE_CHECKING:
    from ..context import CommandContext


def check_argv_for_secrets(context: CommandContext, argv: tuple[str, ...]) -> None:
    """Warn when resolved in-memory secrets appear in process argv.

    Secrets in argv can be visible to process listings on many systems.  Bywaf
    does not block the execution here, but it records a redacted audit event so
    operators can see that a wrapper plugin passed a secret through an unsafe
    channel.
    """
    leaked = leaked_secret_arguments(context, argv)
    if not leaked:
        return
    context.audit_capability("framework.secret.argv")
    if context._db is not None:
        context._db.publish(
            "process.secret.argv",
            {
                "argv": list(redact_process_argv(context, argv)),
                "secret_fingerprints": leaked,
                "job_id": context.job_id,
            },
            "framework",
            pipeline_id=context.pipeline_id,
            command_run_id=context.command_run_id,
            parent_command_run_id=context.parent_command_run_id,
        )


def leaked_secret_arguments(context: CommandContext, argv: tuple[str, ...]) -> list[dict[str, str]]:
    """Return metadata for in-memory secrets that appear in argv text."""
    found: list[dict[str, str]] = []
    for ref, secret_ref in context._secrets.refs.items():
        secret = context._secrets.get(ref)
        if secret and any(secret in arg for arg in argv):
            found.append({"name": secret_ref.name, "fingerprint": secret_ref.fingerprint.format()})
    return found


def redact_process_argv(context: CommandContext, argv: tuple[str, ...]) -> tuple[str, ...]:
    """Redact any known secret values before argv is written to audit events."""
    return tuple(redact_known_secret_values(context, arg) for arg in argv)


def redact_known_secret_values(context: CommandContext, text: str) -> str:
    """Replace known plaintext secret values with the canonical redaction token."""
    value = text
    for ref in context._secrets.refs:
        secret = context._secrets.get(ref)
        if secret:
            value = value.replace(secret, REDACTED_VALUE)
    return value


def audit_process_env(context: CommandContext, env: Mapping[str, str] | None) -> dict[str, Any] | None:
    """Return redacted process environment details for audit events."""
    if env is None:
        return None
    redacted: dict[str, str] = {}
    secrets: list[dict[str, str]] = []
    for key, raw_value in sorted(env.items()):
        # Environment variables are usually a better secret channel than argv,
        # but they still need redaction before they enter durable audit events.
        value = str(raw_value)
        for ref, secret_ref in context._secrets.refs.items():
            secret = context._secrets.get(ref)
            if secret and secret in value:
                secrets.append(
                    {
                        "env": str(key),
                        "name": secret_ref.name,
                        "fingerprint": secret_ref.fingerprint.format(),
                    }
                )
        value = redact_known_secret_values(context, value)
        redacted[str(key)] = value
    return {"env": redacted, "secrets": secrets}
