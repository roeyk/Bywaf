"""Central framework policy helpers.

Provides shared network scope parsing, DNS resolution, and target filtering for
bundled network-facing commandlets.

Used by:
- hostscanner: plan-time target pruning before host discovery.
- portscanner: execution-time filtering before nmap port scans.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from .plugin import split_var_values
from .utils import host_candidates, is_ipv4_range

if TYPE_CHECKING:
    from .plugin import CommandContext

DEFAULT_DENY_NETWORKS = "169.254.169.254/32"
DEFAULT_TARGET_LIMIT = 256


def network_policy(context: CommandContext) -> tuple[tuple[Any, ...], tuple[Any, ...], str]:
    """Return allowed networks, denied networks, and policy mode."""
    allowed = tuple(parse_networks(context.vars.get_global("policy.network.allow", "") or ""))
    denied = tuple(parse_networks(context.vars.get_global("policy.network.deny", DEFAULT_DENY_NETWORKS) or DEFAULT_DENY_NETWORKS))
    mode = context.vars.get_global("policy.network.mode", "warn") or "warn"
    return allowed, denied, mode


def parse_networks(value: str) -> tuple[Any, ...]:
    """Parse comma/space separated network policy values."""
    networks = []
    for item in split_var_values(value):
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            for host in resolve_policy_targets(item):
                networks.append(ipaddress.ip_network(host, strict=False))
    return tuple(networks)


def resolve_policy_targets(target: str) -> tuple[str, ...]:
    """Resolve or expand one target used inside policy configuration."""
    candidates = host_candidates(target)
    if len(candidates) > DEFAULT_TARGET_LIMIT:
        raise ValueError(f"expanded policy target list exceeds limit {DEFAULT_TARGET_LIMIT}")
    resolved: list[str] = []
    for candidate in candidates:
        resolved.extend(resolve_target(candidate))
    return tuple(dict.fromkeys(resolved))


def apply_network_policy(
    targets: Iterable[str],
    allowed: tuple[Any, ...],
    denied: tuple[Any, ...],
) -> tuple[tuple[str, ...], list[str]]:
    """Return target strings allowed by network policy plus warnings."""
    kept: list[str] = []
    warnings: list[str] = []
    for target in targets:
        if is_ipv4_range(target):
            filtered, target_warnings = apply_network_policy(host_candidates(target), allowed, denied)
            if target_warnings:
                warnings.extend(target_warnings)
                kept.extend(filtered)
            else:
                kept.append(target)
            continue
        decision = network_policy_decision(target, allowed, denied)
        if decision:
            warnings.append(decision)
            continue
        kept.append(target)
    return tuple(dict.fromkeys(kept)), warnings


def network_policy_decision(target: str, allowed: tuple[Any, ...], denied: tuple[Any, ...]) -> str:
    """Return a warning string when one target is denied, otherwise empty."""
    target_network = target_as_network(target)
    if target_network is None:
        return f"{target} is not a normalized IP target"
    if any(target_network.overlaps(network) for network in denied):
        return f"{target} is denied by network policy"
    if allowed and not any(target_network.subnet_of(network) for network in allowed):
        return f"{target} is outside allowed network scope"
    return ""


def target_as_network(target: str) -> Any | None:
    """Return an IP network for an address or CIDR target."""
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None


def publish_network_policy_evaluated(
    context: CommandContext,
    *,
    decision: str,
    warnings: Iterable[str],
    before: Iterable[str],
    after: Iterable[str],
) -> None:
    """Persist a framework policy decision when execution-time filtering runs."""
    if context._db is None:
        return
    context._db.publish(
        "policy.evaluated",
        {
            "commandlet": context.source,
            "decision": decision,
            "warnings": list(warnings),
            "before": {"targets": list(before)},
            "after": {"targets": list(after)},
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def resolve_target(target: str) -> tuple[str, ...]:
    """Return an IP literal unchanged or resolve a DNS name to IP addresses."""
    try:
        ipaddress.ip_address(target)
        return (target,)
    except ValueError:
        return resolve_name(target)


def resolve_name(name: str) -> tuple[str, ...]:
    """Resolve a DNS name to stable, unique IP address strings."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host: {name}") from exc

    addresses: list[str] = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        address = str(sockaddr[0])
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"could not resolve host: {name}")
    return tuple(addresses)
