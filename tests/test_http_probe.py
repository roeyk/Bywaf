import contextlib
import http.cookiejar
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.events import Event
from bywaf.http_cookies import load_firefox_cookies
from bywaf.nmap_backend import NmapPort
from bywaf.plugin import CommandContext
from bywaf.plugins.http.http_probe import (
    HttpProbe,
    build_url,
    choose_scheme,
    extract_title,
    probe_targets,
    target_from_text,
)


class HttpProbeTests(unittest.TestCase):
    def test_choose_scheme_auto_uses_https_for_443(self):
        self.assertEqual(choose_scheme(443, "auto"), "https")
        self.assertEqual(choose_scheme(80, "auto"), "http")
        self.assertEqual(choose_scheme(80, "https"), "https")

    def test_build_url_omits_default_ports(self):
        self.assertEqual(build_url("http", "example.test", 80, "/"), "http://example.test/")
        self.assertEqual(build_url("https", "example.test", 443, "admin"), "https://example.test/admin")
        self.assertEqual(build_url("http", "example.test", 8080, "/"), "http://example.test:8080/")

    def test_target_from_text_accepts_url_and_host_port(self):
        self.assertEqual(target_from_text("https://example.test/a", "auto", "/").port, 443)
        target = target_from_text("example.test:8080", "auto", "/")
        self.assertEqual(target.url, "http://example.test:8080/")

    def test_probe_targets_from_port_events(self):
        event = Event.new("port.open", {"host": "127.0.0.1", "port": 443}, "test")
        targets = probe_targets([], [event], "auto", "/")
        self.assertEqual(targets[0].url, "https://127.0.0.1/")

    def test_extract_title(self):
        self.assertEqual(extract_title(b"<html><title> Hello\nWorld </title></html>"), "Hello World")

    def test_http_probe_emits_payload_and_alert(self):
        context = CommandContext(db=None, source="http_probe", metadata={"command_run_id": "run-1"})
        fake_payload = {"ok": True, "status": 200, "final_url": "http://127.0.0.1/"}
        output = io.StringIO()
        with (
            patch("bywaf.plugins.http.http_probe.probe_url", return_value=fake_payload),
            contextlib.redirect_stdout(output),
        ):
            events = list(HttpProbe().run(context, ["127.0.0.1"], []))
        self.assertEqual(events[0]["status"], 200)
        self.assertIn("http_probe <run-1>: discovered HTTP endpoint", output.getvalue())

    def test_http_probe_silent_suppresses_alert(self):
        context = CommandContext(db=None, source="http_probe", metadata={"command_run_id": "run-1"})
        output = io.StringIO()
        with (
            patch("bywaf.plugins.http.http_probe.probe_url", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(output),
        ):
            events = list(HttpProbe().run(context, ["-s", "127.0.0.1"], []))
        self.assertTrue(events[0]["ok"])
        self.assertEqual(output.getvalue(), "")

    def test_http_probe_uses_cookie_file_var(self):
        context = CommandContext(db=None, source="http_probe")
        context.varstore.set("http_probe.cookie-file", "/tmp/cookies.txt")
        with (
            patch("bywaf.plugins.http.http_probe.build_opener") as build_opener,
            patch("bywaf.plugins.http.http_probe.probe_url", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            list(HttpProbe().run(context, ["127.0.0.1"], []))
        self.assertEqual(build_opener.call_args.args[0], "/tmp/cookies.txt")

    def test_http_probe_remembers_explicit_cookie_file(self):
        context = CommandContext(db=None, source="http_probe")
        with (
            patch("bywaf.plugins.http.http_probe.build_opener"),
            patch("bywaf.plugins.http.http_probe.probe_url", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            list(HttpProbe().run(context, ["--cookie-file", "/tmp/cookies.txt", "127.0.0.1"], []))
        self.assertEqual(context.varstore.get("http_probe.cookie-file"), "/tmp/cookies.txt")

    def test_load_firefox_cookies_reads_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp, "cookies.sqlite")
            conn = sqlite3.connect(db)
            try:
                conn.execute(
                    """
                    CREATE TABLE moz_cookies (
                        host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
                        name TEXT, value TEXT
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO moz_cookies VALUES (?, ?, ?, ?, ?, ?)",
                    (".example.test", "/", 1, 2000000000, "session", "abc"),
                )
                conn.commit()
            finally:
                conn.close()
            jar = http.cookiejar.CookieJar()
            load_firefox_cookies(db, jar)
            cookies = list(jar)
            self.assertEqual(cookies[0].name, "session")
            self.assertEqual(cookies[0].value, "abc")


if __name__ == "__main__":
    unittest.main()
