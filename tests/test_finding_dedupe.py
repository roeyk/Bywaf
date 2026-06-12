"""Tests for finding dedupe behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
Coverage focus: finding dedupe regression behavior.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding.dedupe import FindingDedupe, normalize_event


def context_for(db: EventStore) -> CommandContext:
    """Test helper for context for."""
    return CommandContext(
        db=db,
        source="finding_dedupe",
        metadata={"capabilities": FindingDedupe().spec.capabilities},
    )


class FindingDedupeTests(unittest.TestCase):
    """Groups regression coverage for finding dedupe behavior."""
    def test_identifier_match_publishes_new_then_duplicate(self):
        """Protect identifier match publishes new then duplicate behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            first = db.publish(
                "vulnerability.potential",
                {
                    "tool": "nikto",
                    "title": "Apache path traversal CVE-2021-41773",
                    "target": {"scheme": "http", "host": "example.test", "port": 80, "path": "/"},
                    "identifiers": {"cve": ["CVE-2021-41773"]},
                },
                "nikto",
            )
            second = db.publish(
                "vulnerability.potential",
                {
                    "tool": "other",
                    "title": "Apache 2.4.49 traversal vulnerability",
                    "url": "http://example.test/",
                    "identifiers": {"cve": ["CVE-2021-41773"]},
                },
                "other",
            )
            list(FindingDedupe().run(context_for(db), ["-s"], [first, second]))
            self.assertEqual(len(db.events_for_topic("finding.new")), 1)
            duplicate = db.events_for_topic("finding.duplicate")[0].payload
            self.assertEqual(duplicate["duplicate_of"], duplicate["finding_id"])
            self.assertIn("identifier", duplicate["matched_on"])

    def test_target_scope_dedupes_and_preserves_affected_resources(self):
        """Protect target scope dedupes and preserves affected resources behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            first = db.publish(
                "finding.candidate",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"scheme": "https", "host": "example.test", "path": "/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/.git/config", "path": "/.git/config"}],
                    "confidence_basis": "content_indicator",
                    "evidence": "root git config returned",
                    "sources": [{"tool": "http_paths", "topic": "http.path"}],
                },
                "http_paths",
            )
            second = db.publish(
                "finding.candidate",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "target": {"scheme": "https", "host": "example.test", "path": "/app/.git/config"},
                    "identifiers": {"cwe": ["CWE-538"]},
                    "affected": [{"url": "https://example.test/app/.git/config", "path": "/app/.git/config"}],
                    "evidence": "app git config returned",
                    "sources": [{"tool": "repo_exposure", "topic": "repo.git_config.checked"}],
                },
                "repo_exposure",
            )

            list(FindingDedupe().run(context_for(db), ["-s"], [first, second]))

            self.assertEqual(len(db.events_for_topic("finding.new")), 1)
            self.assertEqual(len(db.events_for_topic("finding.duplicate")), 1)
            finding = db.events_for_topic("finding.new")[0].payload
            self.assertEqual(finding["target_scope"], {"kind": "web_origin", "value": "https://example.test"})
            self.assertEqual(finding["identifiers"], {"cwe": ["CWE-538"]})
            self.assertEqual(finding["confidence_basis"], "content_indicator")
            self.assertEqual(
                finding["affected"],
                [
                    {"url": "https://example.test/.git/config", "path": "/.git/config"},
                    {"url": "https://example.test/app/.git/config", "path": "/app/.git/config"},
                ],
            )
            self.assertEqual(
                finding["group_key"],
                "web.exposure.git_config|web_origin:https://example.test|cwe:CWE-538",
            )
            self.assertIn({"tool": "http_paths", "topic": "http.path"}, finding["sources"])
            self.assertIn({"tool": "repo_exposure", "topic": "repo.git_config.checked"}, finding["sources"])

    def test_same_target_and_cwe_different_classes_are_distinct_findings(self):
        """Protect same target and cwe different classes are distinct findings behavior from regressions."""
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            first = db.publish(
                "finding.candidate",
                {
                    "title": "HTTP write-capable methods enabled",
                    "class": "web.method.write_methods_enabled",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "identifiers": {"cwe": ["CWE-650"]},
                },
                "http_methods",
            )
            second = db.publish(
                "finding.candidate",
                {
                    "title": "WebDAV HTTP methods enabled",
                    "class": "web.method.webdav_enabled",
                    "target_scope": {"kind": "web_origin", "value": "https://example.test"},
                    "identifiers": {"cwe": ["CWE-650"]},
                },
                "http_methods",
            )

            list(FindingDedupe().run(context_for(db), ["-s"], [first, second]))

            self.assertEqual(
                {event.payload["class"] for event in db.events_for_topic("finding.new")},
                {"web.method.write_methods_enabled", "web.method.webdav_enabled"},
            )
            self.assertEqual(db.events_for_topic("finding.duplicate"), [])

    def test_status_upgrade_publishes_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            potential = db.publish(
                "vulnerability.potential",
                {
                    "title": "Default credentials on admin panel",
                    "url": "https://example.test/admin",
                    "identifiers": {"cwe": ["CWE-798"]},
                    "affected": [{"url": "https://example.test/admin"}],
                    "verification": "potential",
                },
                "scanner-a",
            )
            confirmed = db.publish(
                "vulnerability.confirmed",
                {
                    "title": "Default credentials confirmed on admin panel",
                    "url": "https://example.test/admin",
                    "identifiers": {"cwe": ["CWE-798"]},
                    "affected": [{"url": "https://example.test/login"}],
                    "verification": "confirmed",
                },
                "scanner-b",
            )
            list(FindingDedupe().run(context_for(db), ["-s"], [potential, confirmed]))
            finding = db.events_for_topic("finding.new")[0].payload
            self.assertEqual(
                finding["affected"],
                [{"url": "https://example.test/admin"}, {"url": "https://example.test/login"}],
            )
            updated = db.events_for_topic("finding.updated")[0].payload
            self.assertEqual(updated["previous_status"], "potential")
            self.assertEqual(updated["new_status"], "confirmed")

    def test_confirmed_finding_topic_is_normalized_as_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            event = db.publish(
                "finding.confirmed",
                {
                    "title": "Exposed Git repository configuration",
                    "class": "web.exposure.git_config",
                    "target": {"host": "example.test", "path": "/.git/config"},
                    "status": "confirmed",
                },
                "scanner",
            )

            normalized = normalize_event(event)

            self.assertEqual(normalized.source_topic, "finding.confirmed")
            self.assertEqual(normalized.status, "confirmed")

    def test_fuzzy_candidate_does_not_auto_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            first = db.publish(
                "vulnerability.potential",
                {
                    "title": "Missing Content-Security-Policy header",
                    "class": "missing_security_header",
                    "url": "https://example.test/",
                },
                "scanner-a",
            )
            second = db.publish(
                "vulnerability.potential",
                {
                    "title": "Content Security Policy header is missing",
                    "class": "missing_security_header",
                    "url": "https://example.test/",
                },
                "scanner-b",
            )
            list(FindingDedupe().run(context_for(db), ["-s", "threshold=0.70"], [first, second]))
            self.assertEqual(len(db.events_for_topic("finding.new")), 1)
            candidate = db.events_for_topic("finding.merge_candidate")[0].payload
            self.assertGreaterEqual(candidate["score"], 0.7)
            self.assertEqual(candidate["matched_on"], ["target", "class", "fuzzy_text"])

    def test_summary_file_is_attached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = EventStore(root / "bywaf.sqlite3")
            event = db.publish(
                "vulnerability.potential",
                {"title": "Directory listing enabled", "url": "http://example.test/"},
                "scanner",
            )
            summary = root / "summary.json"
            list(FindingDedupe().run(context_for(db), ["-s", f"file={summary}"], [event]))
            self.assertTrue(summary.exists())
            self.assertEqual(db.events_for_topic("artifact.attached")[0].payload["name"], "summary.json")

    def test_argparse_usage_uses_bywaf_key_value_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                list(FindingDedupe().run(context_for(db), ["--bad"], []))
            text = stderr.getvalue()
            self.assertIn("finding_dedupe [file=summary.json|summary.md] [format=json|md] [threshold=0.82]", text)
            self.assertNotIn("--file FILE", text)
            self.assertNotIn("--format", text)
            self.assertNotIn("--limit", text)
            self.assertNotIn("--threshold", text)

    def test_normalizer_extracts_embedded_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            event = db.publish(
                "nikto.finding",
                {"message": "Possible issue CVE-2024-12345", "target": {"host": "example.test"}},
                "nikto",
            )
            normalized = normalize_event(event)
            self.assertEqual(normalized.identifiers["cve"], ["CVE-2024-12345"])


if __name__ == "__main__":
    unittest.main()
