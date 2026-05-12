import sys
import types
import unittest
from unittest.mock import patch

from bywaf.nmap_backend import (
    NmapPort,
    NmapScanError,
    NmapUnavailableError,
    collect_open_ports,
    discover_live_hosts,
    discover_live_hosts_libnmap,
    load_backend,
    scan_open_ports_libnmap,
    scan_open_ports,
)


class NmapBackendTests(unittest.TestCase):
    def test_load_backend_prefers_nmaplib(self):
        fake = types.SimpleNamespace(PortScanner=object)

        def import_module(name):
            if name == "nmaplib":
                return fake
            raise ImportError(name)

        with patch("bywaf.nmap_backend.importlib.import_module", side_effect=import_module):
            self.assertEqual(load_backend(), ("nmaplib", fake))

    def test_load_backend_raises_when_missing(self):
        with patch("bywaf.nmap_backend.importlib.import_module", side_effect=ImportError):
            with self.assertRaises(NmapUnavailableError):
                load_backend()

    def test_discover_live_hosts_uses_portscanner_backend(self):
        with patch("bywaf.nmap_backend.load_backend", return_value=("nmaplib", FakeNmapModule)):
            self.assertEqual(discover_live_hosts("127.0.0.1"), ["127.0.0.1"])

    def test_scan_open_ports_uses_portscanner_backend(self):
        with patch("bywaf.nmap_backend.load_backend", return_value=("nmaplib", FakeNmapModule)):
            self.assertEqual(
                scan_open_ports(["127.0.0.1"], "22"),
                [NmapPort("127.0.0.1", 22, "tcp", "open", "ssh", "syn-ack")],
            )

    def test_scan_open_ports_omits_ports_for_default_nmap_scan(self):
        scanner = FakeScanner()

        class Module:
            @staticmethod
            def PortScanner():
                return scanner

        with patch("bywaf.nmap_backend.load_backend", return_value=("nmaplib", Module)):
            scan_open_ports(["127.0.0.1"], None)
        self.assertNotIn("ports", scanner.kwargs)

    def test_discover_live_hosts_supports_libnmap_backend(self):
        backend = fake_libnmap_backend(FakeReport([FakeLibHost("127.0.0.1", "up")]))
        self.assertEqual(discover_live_hosts_libnmap(backend, "127.0.0.1", "-sn"), ["127.0.0.1"])

    def test_scan_open_ports_supports_libnmap_backend(self):
        service = FakeLibService(443, "tcp", "open", "https", "syn-ack")
        backend = fake_libnmap_backend(FakeReport([FakeLibHost("127.0.0.1", "up", [service])]))
        self.assertEqual(
            scan_open_ports_libnmap(backend, ["127.0.0.1"], "443", "-sT"),
            [NmapPort("127.0.0.1", 443, "tcp", "open", "https", "syn-ack")],
        )

    def test_libnmap_scan_omits_p_option_without_ports(self):
        backend = fake_libnmap_backend(FakeReport([]))
        scan_open_ports_libnmap(backend, ["127.0.0.1"], None, "-sT")
        self.assertEqual(backend["process"].last_options, "-sT")

    def test_libnmap_scan_failure_raises(self):
        backend = fake_libnmap_backend(FakeReport([]), failed=True, stderr="permission denied")
        with self.assertRaisesRegex(NmapScanError, "permission denied"):
            discover_live_hosts_libnmap(backend, "127.0.0.1", "-sn")

    def test_collect_open_ports_ignores_closed_ports(self):
        self.assertEqual(
            collect_open_ports(FakeScanner({"tcp": {80: {"state": "closed"}}})),
            [],
        )


class FakeHostResult:
    def __init__(self, protocols=None):
        self.protocols = protocols or {"tcp": {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}}

    def state(self):
        return "up"

    def all_protocols(self):
        return list(self.protocols)

    def __getitem__(self, protocol):
        return self.protocols[protocol]


class FakeScanner:
    def __init__(self, protocols=None):
        self.protocols = protocols

    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult(self.protocols)


class FakeNmapModule:
    PortScanner = FakeScanner


class FakeLibService:
    def __init__(self, port, protocol, state, service="", reason=""):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.reason = reason


class FakeLibHost:
    def __init__(self, address, status, services=None):
        self.address = address
        self.status = status
        self.services = services or []


class FakeReport:
    def __init__(self, hosts):
        self.hosts = hosts


def fake_libnmap_backend(report, failed=False, stderr=""):
    class ProcessModule:
        class NmapProcess:
            def __init__(self, targets, options):
                ProcessModule.last_options = options
                self.targets = targets
                self.options = options
                self.stdout = "<xml />"
                self.stderr = stderr

            def run(self):
                return 0 if not failed else 1

            def has_failed(self):
                return failed

    class ParserModule:
        class NmapParser:
            @staticmethod
            def parse(stdout):
                return report

    return {"process": ProcessModule, "parser": ParserModule}


if __name__ == "__main__":
    unittest.main()
