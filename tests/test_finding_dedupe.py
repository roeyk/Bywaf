"""Tests for finding dedupe behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bywaf.db import EventStore
from bywaf.plugin import CommandContext
from bywaf.plugins.analysis.finding_dedupe import FindingDedupe, normalize_event


def context_for(db: EventStore) -> CommandContext:
    return CommandContext(
        db=db,
        source="finding_dedupe",
        metadata={"capabilities": FindingDedupe().spec.capabilities},
    )


class FindingDedupeTests(unittest.TestCase):
    def test_identifier_match_publishes_new_then_duplicate(self):
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

    def test_status_upgrade_publishes_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = EventStore(Path(tmp, "bywaf.sqlite3"))
            potential = db.publish(
                "vulnerability.potential",
                {
                    "title": "Default credentials on admin panel",
                    "url": "https://example.test/admin",
                    "identifiers": {"cwe": ["CWE-798"]},
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
                    "verification": "confirmed",
                },
                "scanner-b",
            )
            list(FindingDedupe().run(context_for(db), ["-s"], [potential, confirmed]))
            updated = db.events_for_topic("finding.updated")[0].payload
            self.assertEqual(updated["previous_status"], "potential")
            self.assertEqual(updated["new_status"], "confirmed")

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
