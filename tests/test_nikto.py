"""Tests for nikto behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples.

Coverage focus: nikto regression behavior.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bywaf.db import EventStore
from bywaf.event import Event
from bywaf.plugin import CommandContext
from bywaf.plugins.http.nikto import (
    Nikto,
    extract_finding_records,
    finding_identifiers,
    nikto_argv,
    nikto_targets,
    normalize_findings,
)


class NiktoTests(unittest.TestCase):
    """Groups regression coverage for nikto behavior."""
    def test_builds_shell_free_json_argv(self):
        argv = nikto_argv(
            binary="nikto",
            url="https://example.test/",
            output_path=Path("/tmp/out.json"),
            tuning="123",
            plugins="apache",
        )
        self.assertEqual(argv[:7], ["nikto", "-host", "https://example.test/", "-Format", "json", "-output", "/tmp/out.json"])
        self.assertIn("-nointeractive", argv)
        self.assertIn("-Tuning", argv)
        self.assertIn("-Plugins", argv)

    def test_targets_accept_explicit_http_endpoint_and_webfin_events(self):
        http_event = Event.new(
            "http.endpoint",
            {"url": "http://example.test/", "host": "example.test", "port": 80, "scheme": "http"},
            "test",
        )
        webfin_event = Event.new(
            "web.fingerprint",
            {"url": "https://example.test/", "host": "example.test", "port": 443, "interesting": True},
            "test",
        )
        ignored_event = Event.new("web.fingerprint", {"url": "https://ignored.test/", "interesting": False}, "test")

        targets = nikto_targets(["example.test:8080"], [http_event, webfin_event, ignored_event], "all")

        self.assertEqual([target["url"] for target in targets], [
            "http://example.test:8080/",
            "https://example.test/",
            "http://example.test/",
        ])

    def test_extracts_and_normalizes_findings_with_standard_identifiers(self):
        data = {
            "host": "example.test",
            "vulnerabilities": [
                {
                    "id": "999001",
                    "msg": "Potential issue CVE-2024-12345 CWE-79",
                    "url": "/admin",
                    "method": "GET",
                    "OSVDB": "1234",
                }
            ],
        }
        records = extract_finding_records(data)
        self.assertEqual(len(records), 1)
        identifiers = finding_identifiers(records[0])
        self.assertEqual(identifiers["cve"], ["CVE-2024-12345"])
        self.assertEqual(identifiers["cwe"], ["CWE-79"])
        self.assertIn("nikto:999001", identifiers["vendor"])
        self.assertIn("osvdb:1234", identifiers["vendor"])

        findings = normalize_findings(
            {"url": "https://example.test/", "host": "example.test", "port": 443, "scheme": "https"},
            data,
            {"artifact_id": "artifact-1"},
        )
        self.assertEqual(findings[0]["verification"], "potential")
        self.assertEqual(findings[0]["path"], "/admin")
        self.assertEqual(findings[0]["artifact_id"], "artifact-1")

    def test_run_uses_framework_process_and_emits_normalized_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="nikto",
                metadata={
                    "command_run_id": "run-1",
                    "pipeline_id": "pipeline-1",
                    "capabilities": Nikto().spec.capabilities,
                },
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                output_path = Path(argv[argv.index("-output") + 1])
                output_path.write_text(
                    json.dumps(
                        {
                            "vulnerabilities": [
                                {"id": "abc", "msg": "Admin page found", "url": "/admin", "method": "GET"}
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run) as run_process:
                list(Nikto().run(context, ["https://example.test/"], []))

            self.assertEqual(run_process.call_count, 1)
            self.assertEqual(db.events_for_topic("nikto.finding")[0].payload["title"], "Admin page found")
            self.assertEqual(db.events_for_topic("vulnerability.found")[0].payload["verification"], "potential")
            self.assertEqual(db.events_for_topic("vulnerability.potential")[0].payload["scanner"], "nikto")
            self.assertTrue(db.events_for_topic("framework.process.run.requested"))
            self.assertTrue(db.events_for_topic("framework.console.alert.requested"))

    def test_missing_executable_is_reported_as_system_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="nikto",
                metadata={"command_run_id": "run-1", "capabilities": Nikto().spec.capabilities},
            )
            with patch("bywaf.plugin.process.run_process_argv", side_effect=FileNotFoundError("nikto")):
                list(Nikto().run(context, ["https://example.test/"], []))

            system_error = db.events_for_topic("system.error")[0].payload
            self.assertEqual(system_error["tool"], "nikto")
            self.assertIn("not found", system_error["message"])

    def test_invalid_json_error_references_raw_output_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="nikto",
                metadata={
                    "command_run_id": "run-1",
                    "pipeline_id": "pipeline-1",
                    "capabilities": Nikto().spec.capabilities,
                },
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                output_path = Path(argv[argv.index("-output") + 1])
                output_path.write_text("{not json", encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(Nikto().run(context, ["https://example.test/"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertIn("invalid JSON", error["message"])
            self.assertIn("artifact_id", error)
            self.assertTrue(db.events_for_topic("artifact.attached"))

    def test_missing_json_output_is_reported_without_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="nikto",
                metadata={"command_run_id": "run-1", "capabilities": Nikto().spec.capabilities},
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                return subprocess.CompletedProcess(argv, 0, stdout="warning only", stderr="")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(Nikto().run(context, ["https://example.test/"], []))

            error = db.events_for_topic("tool.error")[0].payload
            self.assertEqual(error["message"], "nikto did not produce a JSON output file")
            self.assertIn("artifact_id", error)
            self.assertTrue(db.events_for_topic("artifact.attached"))
            self.assertEqual(db.events_for_topic("finding.candidate"), [])

    def test_nonzero_exit_attaches_process_output_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            context = CommandContext(
                db=db,
                source="nikto",
                metadata={"command_run_id": "run-1", "capabilities": Nikto().spec.capabilities},
            )

            def fake_run(argv, *, cwd=None, env=None, timeout=None):
                return subprocess.CompletedProcess(argv, 2, stdout="partial stdout", stderr="fatal stderr")

            with patch("bywaf.plugin.process.run_process_argv", side_effect=fake_run):
                list(Nikto().run(context, ["https://example.test/"], []))

            errors = [event.payload for event in db.events_for_topic("tool.error")]
            exit_error = next(error for error in errors if "exited with status 2" in error["message"])
            self.assertIn("artifact_id", exit_error)
            self.assertTrue(db.events_for_topic("artifact.attached"))


if __name__ == "__main__":
    unittest.main()
