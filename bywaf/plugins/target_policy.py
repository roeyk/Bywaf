"""Shared target filtering helpers for network-facing plugins."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar

from bywaf.plugin import CommandContext

T = TypeVar("T")


def filter_targets_by_host(
    context: CommandContext,
    targets: Iterable[T],
    host_of: Callable[[T], str],
) -> list[T]:
    """Return targets whose host passes the framework network policy."""
    resolved_targets = list(targets)
    allowed_hosts = set(
        context.policy.filter_network_targets(
            host
            for target in resolved_targets
            if (host := host_of(target))
        )
    )
    return [target for target in resolved_targets if host_of(target) in allowed_hosts]


def filter_host_port_targets(
    context: CommandContext,
    targets: Iterable[tuple[str, int]],
) -> list[tuple[str, int]]:
    """Return host/port pairs whose host passes framework network policy."""
    return filter_targets_by_host(context, targets, lambda target: target[0])
