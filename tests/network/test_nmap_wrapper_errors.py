"""Plugin-level diagnostics for nmap-backed wrappers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.discovery.hostscanner import HostScanner
from bywaf.plugins.network.nmap_backend import NmapScanError, NmapUnavailableError
from bywaf.plugins.network.portscanner import PortScanner


def make_context(tmp: str, source: str, capabilities: tuple[str, ...]) -> tuple[CommandContext, EventStore]:
    """Build a direct commandlet context with a real event store."""
    db = EventStore(Path(tmp, "bywaf.sqlite3"))
    return CommandContext(
        db=db,
        source=source,
        metadata={
            "command_run_id": f"{source}-run",
            "capabilities": capabilities,
        },
    ), db


class NmapWrapperErrorTests(unittest.TestCase):
    """Groups regression coverage for plugin-level diagnostics for nmap-backed wrappers."""
    def test_hostscanner_records_missing_backend_as_tool_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(
                tmp,
                "hostscanner",
                (
                    "db.write:name.resolved",
                    "db.write:tool.error",
                    "framework.console.alert",
                    "framework.console.output",
                    "network.connect",
                    "variable.read",
                ),
            )

            with patch(
                "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                side_effect=NmapUnavailableError("missing nmap backend"),
            ):
                events = list(HostScanner().run(context, ["127.0.0.1"], []))

            self.assertEqual(events, [])
            self.assertEqual(db.events_for_topic("host.found"), [])
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["tool"], "nmap")
            self.assertEqual(error["phase"], "host_discovery")
            self.assertEqual(error["exception"], "NmapUnavailableError")
            self.assertEqual(error["message"], "missing nmap backend")

    def test_hostscanner_records_scan_failure_as_tool_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(
                tmp,
                "hostscanner",
                (
                    "db.write:name.resolved",
                    "db.write:tool.error",
                    "framework.console.alert",
                    "framework.console.output",
                    "network.connect",
                    "variable.read",
                ),
            )

            with patch(
                "bywaf.plugins.discovery.hostscanner.discover_live_hosts",
                side_effect=NmapScanError("permission denied"),
            ):
                events = list(HostScanner().run(context, ["127.0.0.1"], []))

            self.assertEqual(events, [])
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["exception"], "NmapScanError")
            self.assertEqual(error["message"], "permission denied")

    def test_portscanner_records_missing_backend_as_tool_error_and_failed_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(
                tmp,
                "portscanner",
                (
                    "db.write:finding.candidate",
                    "db.write:name.resolved",
                    "db.write:tool.error",
                    "framework.console.alert",
                    "framework.console.output",
                    "network.connect",
                    "plugin.progress",
                    "variable.read",
                ),
            )

            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                side_effect=NmapUnavailableError("missing nmap backend"),
            ):
                events = list(PortScanner().run(context, ["127.0.0.1"], []))

            self.assertEqual(events, [])
            self.assertEqual(db.events_for_topic("port.open"), [])
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["tool"], "nmap")
            self.assertEqual(error["phase"], "port_scan")
            self.assertEqual(error["exception"], "NmapUnavailableError")
            failed = db.events_for_topic("plugin.progress.failed")[0].payload
            self.assertEqual(failed["phase"], "port_scan")
            self.assertEqual(failed["error"], "missing nmap backend")

    def test_portscanner_records_scan_failure_without_finding_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, db = make_context(
                tmp,
                "portscanner",
                (
                    "db.write:finding.candidate",
                    "db.write:name.resolved",
                    "db.write:tool.error",
                    "framework.console.alert",
                    "framework.console.output",
                    "network.connect",
                    "plugin.progress",
                    "variable.read",
                ),
            )

            with patch(
                "bywaf.plugins.network.portscanner.scan_open_ports",
                side_effect=NmapScanError("scan failed"),
            ):
                events = list(PortScanner().run(context, ["127.0.0.1"], []))

            self.assertEqual(events, [])
            self.assertEqual(db.events_for_topic("finding.candidate"), [])
            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["exception"], "NmapScanError")
            self.assertEqual(error["message"], "scan failed")


if __name__ == "__main__":
    unittest.main()
