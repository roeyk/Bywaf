"""Nmap-backed scanning helpers.

The adapter prefers a module named ``nmaplib`` when available, but also
supports the common ``python-nmap`` import name (``nmap``) and ``nmapthon``.
Tests patch these functions, so the framework does not require nmap on the
developer machine just to run the suite.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any


class NmapUnavailableError(RuntimeError):
    """Raised when no supported Python nmap binding is installed."""


class NmapScanError(RuntimeError):
    """Raised when nmap executes but reports a scan failure."""


@dataclass(frozen=True, slots=True)
class NmapPort:
    host: str
    port: int
    protocol: str
    state: str
    service: str = ""
    reason: str = ""


def discover_live_hosts(target: str, arguments: str = "-sn") -> list[str]:
    backend_name, backend = load_backend()
    match backend_name:
        case "libnmap":
            return discover_live_hosts_libnmap(backend, target, arguments)
        case "nmapthon":
            return discover_live_hosts_nmapthon(backend, target, arguments)
        case _:
            scanner = backend.PortScanner()
            scanner.scan(hosts=target, arguments=arguments)
            return [
                host
                for host in scanner.all_hosts()
                if host_state(scanner, host) in {"up", "unknown", ""}
            ]


def scan_open_ports(
    targets: list[str],
    ports: str | None = None,
    arguments: str = "-sT",
) -> list[NmapPort]:
    if not targets:
        return []
    backend_name, backend = load_backend()
    match backend_name:
        case "libnmap":
            return scan_open_ports_libnmap(backend, targets, ports, arguments)
        case "nmapthon":
            return scan_open_ports_nmapthon(backend, targets, ports, arguments)
        case _:
            scanner = backend.PortScanner()
            kwargs = {"hosts": " ".join(targets), "arguments": arguments}
            if ports:
                kwargs["ports"] = ports
            scanner.scan(**kwargs)
            return collect_open_ports(scanner)


def load_backend() -> tuple[str, Any]:
    for name in ("nmaplib", "nmap", "nmapthon", "libnmap"):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if name == "libnmap":
            try:
                process = importlib.import_module("libnmap.process")
                parser = importlib.import_module("libnmap.parser")
            except ImportError:
                continue
            return name, {"process": process, "parser": parser}
        if name == "nmapthon" and hasattr(module, "NmapScanner"):
            return name, module
        if hasattr(module, "PortScanner"):
            return name, module
    raise NmapUnavailableError(
        "No supported nmap Python binding found. Install nmap plus nmaplib, python-nmap, "
        "nmapthon, or libnmap."
    )


def host_state(scanner: Any, host: str) -> str:
    host_result = scanner[host]
    state = getattr(host_result, "state", None)
    return state() if callable(state) else ""


def collect_open_ports(scanner: Any) -> list[NmapPort]:
    ports: list[NmapPort] = []
    for host in scanner.all_hosts():
        host_result = scanner[host]
        for protocol in host_result.all_protocols():
            for port in sorted(host_result[protocol].keys()):
                data = host_result[protocol][port]
                if data.get("state") == "open":
                    ports.append(
                        NmapPort(
                            host=host,
                            port=int(port),
                            protocol=str(protocol),
                            state=data.get("state", ""),
                            service=data.get("name", ""),
                            reason=data.get("reason", ""),
                        )
                    )
    return ports


def discover_live_hosts_libnmap(backend: dict[str, Any], target: str, arguments: str) -> list[str]:
    report = run_libnmap_scan(backend, target, arguments)
    return [
        host.address
        for host in report.hosts
        if getattr(host, "status", "") in {"up", "unknown", ""}
    ]


def scan_open_ports_libnmap(
    backend: dict[str, Any],
    targets: list[str],
    ports: str | None,
    arguments: str,
) -> list[NmapPort]:
    options = f"{arguments} -p {ports}".strip() if ports else arguments
    report = run_libnmap_scan(backend, " ".join(targets), options)
    results: list[NmapPort] = []
    for host in report.hosts:
        for service in getattr(host, "services", []):
            state = getattr(service, "state", "")
            if state == "open":
                results.append(
                    NmapPort(
                        host=host.address,
                        port=int(getattr(service, "port", 0)),
                        protocol=str(getattr(service, "protocol", "tcp")),
                        state=state,
                        service=str(getattr(service, "service", "")),
                        reason=str(getattr(service, "reason", "")),
                    )
                )
    return results


def run_libnmap_scan(backend: dict[str, Any], targets: str, options: str) -> Any:
    scanner = backend["process"].NmapProcess(targets=targets, options=options)
    scanner.run()
    if scanner.has_failed():
        raise NmapScanError(scanner.stderr.strip() or "nmap scan failed")
    return backend["parser"].NmapParser.parse(scanner.stdout)


def discover_live_hosts_nmapthon(backend: Any, target: str, arguments: str) -> list[str]:
    scanner = backend.NmapScanner([target], arguments=arguments)
    scanner.run()
    return [
        host
        for host in scanner.scanned_hosts()
        if scanner.state(host) in {"up", "unknown", ""}
    ]


def scan_open_ports_nmapthon(
    backend: Any,
    targets: list[str],
    ports: str | None,
    arguments: str,
) -> list[NmapPort]:
    parsed_ports = [int(port) for port in ports.replace("-", ",").split(",") if port] if ports else None
    kwargs = {"arguments": arguments}
    if parsed_ports:
        kwargs["ports"] = parsed_ports
    scanner = backend.NmapScanner(targets, **kwargs)
    scanner.run()
    results: list[NmapPort] = []
    for host in scanner.scanned_hosts():
        for protocol in scanner.all_protocols(host):
            for port in scanner.scanned_ports(host, protocol):
                state, reason = scanner.port_state(host, protocol, port)
                if state == "open":
                    results.append(
                        NmapPort(
                            host=host,
                            port=int(port),
                            protocol=str(protocol),
                            state=state,
                            reason=reason,
                        )
                    )
    return results
