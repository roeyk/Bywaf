"""Shared target filtering helpers for network-facing plugins.

Used by:
- HTTP, network, and scanner-wrapper plugins before opening outbound
  connections.
- Tests that verify scoped commandlets respect framework network policy.
"""

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
    """Return targets whose host passes the framework network policy.

    Called by: network-facing plugins after parsing candidate targets but
    before capability-audited network IO.
    """
    # Resolve each host once. Some callers derive hostnames by parsing URLs or
    # target dictionaries, so caching avoids repeating that work for allowed
    # targets.
    resolved_targets = [(target, host_of(target)) for target in targets]
    allowed_hosts = set(
        context.policy.filter_network_targets(
            host
            for _, host in resolved_targets
            if host
        )
    )
    # Preserve original target order so commandlet output remains predictable.
    return [target for target, host in resolved_targets if host in allowed_hosts]


def filter_host_port_targets(
    context: CommandContext,
    targets: Iterable[tuple[str, int]],
) -> list[tuple[str, int]]:
    """Return host/port pairs whose host passes framework network policy.

    Called by: plugins that already normalized targets to `(host, port)`.
    """
    return filter_targets_by_host(context, targets, lambda target: target[0])
