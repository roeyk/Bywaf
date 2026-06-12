"""Tests for finding report behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: finding report regression behavior.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bywaf.db import EventStore
from bywaf.app import make_runner
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding.report import FindingReport, infer_export_format


def context_for(db: EventStore) -> CommandContext:
    """Test helper for constructing a finding-report command context."""
    return CommandContext(
        db=db,
        source="finding_report",
        metadata={"capabilities": FindingReport().spec.capabilities},
    )


class FindingReportTests(unittest.TestCase):
    """Groups regression coverage for finding report behavior."""
    def test_report_renders_deduped_findings_as_framework_table(self):
        """Protect report renders deduped findings as framework table behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            finding = db.publish(
                "finding.new",
                {
                    "title": "Missing Content-Security-Policy header",
                    "description": "CSP header is absent",
                    "target": {"scheme": "https", "host": "example.test", "port": "443", "path": "/"},
                    "identifiers": {"cve": ["CVE-2026-0001"]},
                    "severity": "medium",
                    "recommendation": "Add a Content-Security-Policy header.",
                },
                "finding_dedupe",
            )
            list(FindingReport().run(context_for(db), [], [finding]))
            request = db.events_for_topic("framework.render.table.requested")[0]
            self.assertEqual(request.payload["columns"][0]["title"], "Finding name")
            row = request.payload["rows"][0]
            self.assertEqual(row["finding_name"], "Missing Content-Security-Policy header")
            self.assertEqual(row["hosts_affected"], "https://example.test:443/")
            self.assertEqual(row["cve"], "CVE-2026-0001")

    def test_report_falls_back_to_raw_tool_findings(self):
        """Protect report falls back to raw tool findings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            event = db.publish(
                "vulnerability.potential",
                {
                    "title": "Directory listing enabled",
                    "url": "http://example.test/files",
                    "severity": "low",
                },
                "scanner",
            )
            list(FindingReport().run(context_for(db), ["source=tools"], [event]))
            row = db.events_for_topic("framework.render.table.requested")[0].payload["rows"][0]
            self.assertEqual(row["finding_name"], "Directory listing enabled")
            self.assertIn("directory", row["recommendation"].lower())

    def test_export_infers_format_and_attaches_artifact(self):
        """Protect export infers format and attaches artifact behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = EventStore(root / "bywaf.sqlite3")
            event = db.publish(
                "finding.new",
                {
                    "title": "Known vulnerable component",
                    "class": "known_vulnerable_component",
                    "target": {"host": "example.test"},
                    "severity": "high",
                },
                "finding_dedupe",
            )
            output = root / "findings.csv"
            list(FindingReport().run(context_for(db), [f"export={output}"], [event]))
            self.assertTrue(output.exists())
            self.assertIn("Finding name", output.read_text())
            self.assertEqual(db.events_for_topic("artifact.attached")[0].payload["name"], "findings.csv")

    def test_export_format_is_inferred_from_suffix(self):
        """Protect export format is inferred from suffix behavior from regressions."""
        self.assertEqual(infer_export_format(Path("report.docx"), "md"), "docx")
        self.assertEqual(infer_export_format(Path("report.xlsx"), "md"), "xlsx")
        self.assertEqual(infer_export_format(Path("report.json"), "md"), "jsonl")
        self.assertEqual(infer_export_format(Path("report.unknown"), "csv"), "csv")

    def test_argparse_usage_uses_bywaf_key_value_style(self):
        """Protect argparse usage uses bywaf key value style behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                list(FindingReport().run(context_for(db), ["--bad"], []))
            text = stderr.getvalue()
            self.assertIn("finding_report [source=auto|dedupe|tools|all] [export=report.md] [--candidates]", text)
            self.assertNotIn("--export EXPORT", text)
            self.assertNotIn("--file FILE", text)
            self.assertNotIn("--format", text)
            self.assertNotIn("--limit", text)
            self.assertNotIn("--source", text)

    def test_pipeline_report_uses_preceding_dedupe_output(self):
        """Protect pipeline report uses preceding dedupe output behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "vulnerability.potential",
                {
                    "title": "Missing Content-Security-Policy header",
                    "class": "missing_security_header",
                    "url": "https://example.test/",
                    "severity": "medium",
                },
                "scanner",
            )
            runner.execute("finding_dedupe -s | finding_report")
            request = runner.db.events_for_topic("framework.render.table.requested")[0]
            row = request.payload["rows"][0]
            self.assertEqual(row["finding_name"], "Missing Content-Security-Policy header")
            self.assertEqual(runner.db.events_for_topic("finding.new")[0].command_run_id, request.parent_command_run_id)

    def test_pipeline_report_preserves_deduped_affected_resources(self):
        """Protect pipeline report preserves deduped affected resources behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = make_runner(Path(tmp, "bywaf.sqlite3"))
            runner.db.publish(
                "finding.candidate",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/.git/config", "host": "example.test", "path": "/.git/config"}],
                    "severity": "high",
                },
                "http_paths",
            )
            runner.db.publish(
                "finding.candidate",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/app/.git/config", "host": "example.test", "path": "/app/.git/config"}],
                    "severity": "high",
                },
                "repo_exposure",
            )

            runner.execute("finding_dedupe -s | finding_report")

            request = runner.db.events_for_topic("framework.render.table.requested")[0]
            row = request.payload["rows"][0]
            self.assertEqual(row["finding_name"], "Exposed Git repository configuration")
            self.assertEqual(
                row["hosts_affected"],
                "https://example.test/.git/config; https://example.test/app/.git/config",
            )
            self.assertEqual(row["cve"], "")


if __name__ == "__main__":
    unittest.main()
