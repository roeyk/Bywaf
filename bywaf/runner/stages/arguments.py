"""Runner stage argument normalization and redaction helpers.

Used by: `runner.stages.execute_stage()` and lifecycle publishers to convert
public commandlet argument syntax, classify database access, and redact secret
values before audit events are persisted.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast

from ...plugin import CommandContext
from ...plugin.capabilities import DATABASE_ACTIONS
from ...secret.store import REDACTED_VALUE, fingerprint_secret, load_fingerprint_key


def normalize_valued_option_args(plugin, args: list[str]) -> list[str]:
    """Convert public `name=value` syntax into argparse `--name value` pairs."""
    # Convert only declared valued options. Listener/runtime flags and
    # positional values containing `=` are left in their original form.
    valued_options = {option.name for option in plugin.spec.options if option.name not in {"listen", "silent"}}
    normalized: list[str] = []
    for arg in args:
        if "=" not in arg or arg.startswith("--"):
            normalized.append(arg)
            continue
        key, value = arg.split("=", 1)
        if key not in valued_options:
            normalized.append(arg)
            continue
        normalized.extend((f"--{key}", value))
    return normalized


def effective_database_actions(plugin, args: list[str]) -> tuple[str, ...]:
    """Return the effective DB action class for this commandlet invocation."""
    classifier = getattr(plugin, "database_actions_for_args", None)
    actions: Iterable[str] = (
        cast(Iterable[str], classifier(args))
        if callable(classifier)
        else plugin.spec.database_actions
    )
    seen: set[str] = set()
    normalized: list[str] = []
    for action in actions:
        value = str(action)
        if value not in DATABASE_ACTIONS:
            raise ValueError(f"{plugin.spec.name} returned unknown database action: {value}")
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return tuple(action for action in DATABASE_ACTIONS if action in seen) if normalized else tuple()


def redact_commandlet_args(context: CommandContext, plugin, args: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Redact declared secret commandlet options while preserving provenance."""
    # Normalize declared secret option names once so both --name and name=value
    # argument styles can be compared against the same set.
    secret_options = {option.name.strip().lower().replace("_", "-") for option in plugin.spec.options if option.secret}
    if not secret_options:
        return list(args), []
    redacted: list[str] = []
    secrets: list[dict[str, str]] = []
    pending_secret_option: str | None = None
    for arg in args:
        # Handle `--secret value`, where the sensitive value appears in the
        # token after the option name.
        if pending_secret_option is not None:
            redacted.append(REDACTED_VALUE)
            secrets.append(secret_arg_metadata(context, pending_secret_option, arg))
            pending_secret_option = None
            continue
        option_name, value, style = split_option_arg(arg)
        if option_name is not None and option_name in secret_options:
            # Handle `--secret=value` and `secret=value` while keeping enough
            # style information to preserve the operator-visible argument shape.
            if value is None:
                redacted.append(f"--{option_name}")
                pending_secret_option = option_name
                continue
            secrets.append(secret_arg_metadata(context, option_name, value))
            redacted.append(f"--{option_name}={REDACTED_VALUE}" if style == "long-equals" else f"{option_name}={REDACTED_VALUE}")
            continue
        redacted.append(arg)
    return redacted, secrets


def split_option_arg(arg: str) -> tuple[str | None, str | None, str]:
    """Return normalized option name/value/style for long options and key=value."""
    if arg.startswith("--") and "=" in arg:
        key, value = arg[2:].split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "long-equals"
    if arg.startswith("--"):
        return arg[2:].strip().lower().replace("_", "-"), None, "long"
    if "=" in arg:
        key, value = arg.split("=", 1)
        return key.strip().lower().replace("_", "-"), value, "key-equals"
    return None, None, ""


def secret_arg_metadata(context: CommandContext, name: str, value: str) -> dict[str, str]:
    """Return audit-safe metadata for one secret argument value."""
    secret_ref = context._secrets.metadata(value)
    if secret_ref is not None:
        return {"name": secret_ref.name, "option": name, "fingerprint": secret_ref.fingerprint.format()}
    return {
        "name": name,
        "option": name,
        "fingerprint": fingerprint_secret(value, load_fingerprint_key()).format(),
    }


def redact_secret_reference_args(context: CommandContext, args: list[str]) -> list[str]:
    """Redact expanded args that are direct secret references."""
    redacted: list[str] = []
    for arg in args:
        if context._secrets.metadata(arg) is not None:
            redacted.append(REDACTED_VALUE)
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            if context._secrets.metadata(value) is not None:
                redacted.append(f"{key}={REDACTED_VALUE}")
                continue
        redacted.append(arg)
    return redacted
