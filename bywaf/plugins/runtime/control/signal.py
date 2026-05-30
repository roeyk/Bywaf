"""Runtime signal argument parsing.

Keeps signal-specific syntax handling separate from framework action dispatch.

Used by:
- runtime.control: parse `signal` commandlet arguments."""

from __future__ import annotations

from .selectors import parse_target


def parse_signal_args(args: list[str]) -> dict[str, object]:
    """Parse `signal target action [--soft|--hard] [key=value ...]`."""
    if len(args) < 2:
        raise ValueError("signal requires target and action")
    kind, target_id = parse_target(args[0])
    action = normalize_signal_action(args[1])
    if action.startswith("--"):
        raise ValueError("signal requires an action after the target")
    mode = signal_default_mode(action)
    payload_args: dict[str, str] = {}
    for token in args[2:]:
        match token:
            case "--hard" | "--force":
                mode = "hard"
            case "--soft":
                mode = "soft"
            case _ if "=" in token:
                key, value = token.split("=", 1)
                if not key or not value:
                    raise ValueError(f"invalid signal argument: {token}")
                payload_args[key] = value
            case _:
                raise ValueError(f"invalid signal argument: {token}")
    return {"kind": kind, "target_id": target_id, "action": action, "args": payload_args, "mode": mode}


def normalize_signal_action(action: str) -> str:
    """Normalize live-control action aliases to their canonical signal names."""
    return "end" if action == "kill" else action


def signal_default_mode(action: str) -> str:
    """Return the default control mode for a signal action."""
    del action
    return "soft"
