"""Shared address-family helpers for bundled network-facing plugins.

Provides small, framework-independent helpers for interpreting operator IP
family choices such as `-4` and `-6`.

Used by:
- bundled commandlets: keep DNS pre-resolution aligned with plugin arguments.
- tests and future plugin helpers: avoid copying address-family filtering."""

from __future__ import annotations

import ipaddress
import shlex
from collections.abc import Iterable


def filter_addresses_for_ip_family(addresses: Iterable[str], arguments: str) -> tuple[str, ...]:
    """Return only addresses matching `-4` or `-6` flags in an argument string."""
    tokens = set(shlex.split(arguments))
    if "-4" in tokens and "-6" not in tokens:
        return tuple(address for address in addresses if ip_version(address) == 4)
    if "-6" in tokens and "-4" not in tokens:
        return tuple(address for address in addresses if ip_version(address) == 6)
    return tuple(addresses)


def ip_version(address: str) -> int | None:
    """Return IP version for literal addresses and None for non-address strings."""
    try:
        return ipaddress.ip_address(address).version
    except ValueError:
        return None


def scan_target_ip_version(target: str) -> int | None:
    """Return IP version for an IP scan target, including networks and ranges."""
    try:
        return ipaddress.ip_address(target).version
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(target, strict=False).version
    except ValueError:
        pass
    if "-" in target:
        base = target.split("-", 1)[0]
        try:
            return ipaddress.ip_address(base).version
        except ValueError:
            return None
    return None


def target_matches_ip_family(target: str, arguments: str) -> bool:
    """Return whether a scan target matches `-4` or `-6` arguments."""
    version = scan_target_ip_version(target)
    tokens = set(shlex.split(arguments))
    if "-4" in tokens and "-6" not in tokens:
        return version == 4
    if "-6" in tokens and "-4" not in tokens:
        return version == 6
    return True


def is_ip_scan_target(target: str) -> bool:
    """Return whether a target is an IP literal, CIDR network, or IP range."""
    return scan_target_ip_version(target) is not None
