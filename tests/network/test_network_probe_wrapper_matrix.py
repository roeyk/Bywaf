"""Fixture-backed network probe wrapper coverage.

Coverage focus: network network probe wrapper matrix regression behavior.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.network.snmp_get import SnmpGet
from bywaf.plugins.network.tcp_banner import tcp_banner


class TcpBannerWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed network probe wrapper coverage."""
    def test_tcp_banner_emits_error_payload_for_socket_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="tcp_banner", metadata={"capabilities": tcp_banner.spec.capabilities})

            with patch("bywaf.plugins.network.tcp_banner.grab_tcp_banner", return_value={"error": "connection refused", "elapsed_ms": 3}):
                events = list(tcp_banner.run(context, ["192.0.2.10:22"], []))

            self.assertEqual(events[0]["host"], "192.0.2.10")
            self.assertEqual(events[0]["port"], 22)
            self.assertEqual(events[0]["error"], "connection refused")
            self.assertEqual(events[0]["banner"], "")


class SnmpGetWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed network probe wrapper coverage."""
    def test_snmp_get_publishes_successful_value(self):
        fake_hlapi = fake_snmp_hlapi((None, 0, 0, [("1.2.3", "router")]))

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="snmp_get", metadata={"capabilities": SnmpGet().spec.capabilities})

            with patch("bywaf.plugins.network.snmp_get.optional_module", return_value=fake_hlapi):
                list(SnmpGet().run(context, ["host"], []))

            value = db.events_for_topic("snmp.value")[0].payload
            self.assertEqual(value["host"], "host")
            self.assertEqual(value["oid"], "1.2.3")
            self.assertEqual(value["value"], "router")

    def test_snmp_get_preserves_iterator_failure_as_value_error(self):
        fake_hlapi = fake_snmp_hlapi(RuntimeError("transport failed"))

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="snmp_get", metadata={"capabilities": SnmpGet().spec.capabilities})

            with patch("bywaf.plugins.network.snmp_get.optional_module", return_value=fake_hlapi):
                list(SnmpGet().run(context, ["host"], []))

            value = db.events_for_topic("snmp.value")[0].payload
            self.assertEqual(value["host"], "host")
            self.assertIn("transport failed", value["error"])


def fake_snmp_hlapi(result):
    class Constructor:
        def __call__(self, *args, **kwargs):
            del kwargs
            return args[0] if args else object()

    def get_cmd(*args, **kwargs):
        del args, kwargs
        if isinstance(result, Exception):
            raise result
        return iter([result])

    return SimpleNamespace(
        SnmpEngine=Constructor(),
        CommunityData=Constructor(),
        UdpTransportTarget=Constructor(),
        ContextData=Constructor(),
        ObjectType=Constructor(),
        ObjectIdentity=Constructor(),
        getCmd=get_cmd,
    )
