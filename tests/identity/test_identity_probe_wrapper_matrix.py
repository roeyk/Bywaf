"""Fixture-backed identity probe wrapper coverage.

Coverage focus: identity identity probe wrapper matrix regression behavior.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.identity.ldap_probe import LdapProbe
from bywaf.plugins.identity.smb_probe import SmbProbe


class LdapProbeWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed identity probe wrapper coverage."""
    def test_ldap_probe_publishes_bound_server_metadata(self):
        fake_server = SimpleNamespace(info=SimpleNamespace(naming_contexts=["dc=example,dc=test"]))
        fake_ldap = SimpleNamespace(
            ALL="ALL",
            Server=Mock(return_value=fake_server),
            Connection=Mock(return_value=SimpleNamespace(bound=True, unbind=Mock())),
        )

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="ldap_probe", metadata={"capabilities": LdapProbe().spec.capabilities})

            with patch("bywaf.plugins.identity.ldap_probe.optional_module", return_value=fake_ldap):
                list(LdapProbe().run(context, ["dc.example.test"], []))

            server = db.events_for_topic("ldap.server")[0].payload
            self.assertTrue(server["bound"])
            self.assertEqual(server["naming_contexts"], ["dc=example,dc=test"])

    def test_ldap_probe_preserves_bind_failure_as_server_error(self):
        fake_ldap = SimpleNamespace(
            ALL="ALL",
            Server=Mock(return_value=SimpleNamespace(info=None)),
            Connection=Mock(side_effect=RuntimeError("invalid credentials")),
        )

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="ldap_probe", metadata={"capabilities": LdapProbe().spec.capabilities})

            with patch("bywaf.plugins.identity.ldap_probe.optional_module", return_value=fake_ldap):
                list(LdapProbe().run(context, ["dc.example.test"], []))

            server = db.events_for_topic("ldap.server")[0].payload
            self.assertFalse(server["bound"])
            self.assertIn("invalid credentials", server["error"])


class SmbProbeWrapperMatrixTests(TestCase):
    """Groups regression coverage for fixture-backed identity probe wrapper coverage."""
    def test_smb_probe_preserves_connection_failure_as_server_error(self):
        fake_smb = SimpleNamespace(SMBConnection=Mock(side_effect=RuntimeError("connection refused")))

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="smb_probe", metadata={"capabilities": SmbProbe().spec.capabilities})

            with patch("bywaf.plugins.identity.smb_probe.optional_module", return_value=fake_smb):
                list(SmbProbe().run(context, ["host"], []))

            server = db.events_for_topic("smb.server")[0].payload
            self.assertEqual(server["host"], "host")
            self.assertIn("connection refused", server["error"])

    def test_smb_probe_preserves_login_failure_as_server_error(self):
        fake_conn = Mock()
        fake_conn.login.side_effect = RuntimeError("logon failure")
        fake_smb = SimpleNamespace(SMBConnection=Mock(return_value=fake_conn))

        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(db=db, source="smb_probe", metadata={"capabilities": SmbProbe().spec.capabilities})

            with patch("bywaf.plugins.identity.smb_probe.optional_module", return_value=fake_smb):
                list(SmbProbe().run(context, ["username=user", "password=secret", "host"], []))

            server = db.events_for_topic("smb.server")[0].payload
            self.assertIn("logon failure", server["error"])
            self.assertTrue(fake_conn.close.called)
