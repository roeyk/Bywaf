"""General-purpose utility helpers.

Provides small filesystem, path completion, and normalization helpers shared by
modules that should not depend on larger subsystems.

Used by:
- completion and command parsing: complete paths and normalize inputs.
- plugins and tests: reuse low-level helpers."""


from __future__ import annotations

import ipaddress
from itertools import product
import shlex
import socket
from pathlib import Path


def split_pipeline(command_line: str) -> tuple[list[str], bool]:
    """Split a command line on shell-like pipe tokens and detect trailing background."""
    tokens = shlex.split(command_line)
    background = bool(tokens and tokens[-1] == "&")
    if background:
        tokens = tokens[:-1]
    parts: list[list[str]] = [[]]
    for token in tokens:
        match token:
            case "|":
                # shlex makes | a token only when surrounded by whitespace,
                # matching the command syntax documented for Bywaf pipelines.
                parts.append([])
            case _:
                parts[-1].append(token)
    return [" ".join(shlex.quote(token) for token in part) for part in parts if part], background


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse comma/range port syntax such as `22,80,8000-8010`."""
    # First expand comma-separated scalars and inclusive ranges, then validate
    # the unified list so all error paths use the same range check.
    ports: list[int] = []
    for chunk in value.split(","):
        if "-" in chunk:
            start, end = [int(part) for part in chunk.split("-", 1)]
            ports.extend(range(start, end + 1))
        elif chunk.strip():
            ports.append(int(chunk))
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
    return tuple(dict.fromkeys(ports))


def host_candidates(value: str) -> tuple[str, ...]:
    """Expand CIDR and IPv4 range expressions into concrete host strings."""
    if is_ipv4_range(value):
        return expand_ipv4_range(value)
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return (value,)
    return tuple(str(ip) for ip in network.hosts()) or (str(network.network_address),)


def is_ipv4_range(value: str) -> bool:
    """Return True for dotted IPv4 expressions containing dash ranges."""
    parts = value.split(".")
    return len(parts) == 4 and any("-" in part for part in parts)


def expand_ipv4_range(value: str) -> tuple[str, ...]:
    """Expand forms like `192.168.1-3.1-255`."""
    # Parse each octet independently, then take the Cartesian product so compact
    # dotted range syntax can expand across more than one octet.
    parts = value.split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 range: {value}")
    octets = [parse_octet_range(part) for part in parts]
    return tuple(".".join(str(part) for part in combo) for combo in product(*octets))


def parse_octet_range(value: str) -> tuple[int, ...]:
    """Parse one IPv4 octet or inclusive octet range."""
    if "-" in value:
        start_text, end_text = value.split("-", 1)
        start = parse_octet(start_text)
        end = parse_octet(end_text)
        if start > end:
            raise ValueError(f"invalid descending IPv4 octet range: {value}")
        return tuple(range(start, end + 1))
    return (parse_octet(value),)


def parse_octet(value: str) -> int:
    """Validate and return one IPv4 octet."""
    if not value.isdigit():
        raise ValueError(f"invalid IPv4 octet: {value}")
    octet = int(value)
    if not 0 <= octet <= 255:
        raise ValueError(f"IPv4 octet out of range: {value}")
    return octet


def can_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Best-effort TCP connect helper used by fallback checks/tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def complete_path(prefix: str, root: Path | str = ".") -> list[str]:
    """Return filesystem completion candidates relative to a root."""
    root_path = Path(root)
    path = Path(prefix)
    directory = root_path / path.parent if str(path.parent) != "." else root_path
    stem = path.name
    if not directory.exists():
        return []
    results = []
    for child in directory.iterdir():
        if child.name.startswith(stem):
            # Append slash for directories so users can keep completing deeper
            # paths without guessing the entry type.
            suffix = "/" if child.is_dir() else ""
            results.append(str(path.parent / f"{child.name}{suffix}") if str(path.parent) != "." else f"{child.name}{suffix}")
    return sorted(results)
