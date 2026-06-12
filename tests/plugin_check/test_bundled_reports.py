"""Plugin checker tests for test bundled reports.

Coverage focus: plugin check bundled reports regression behavior.
"""

import json
import unittest

from scripts.plugin_check import check_bundled_plugins, main
from tests.plugin_check_fixtures import capture_stdout


class TestBundledReportsTests(unittest.TestCase):
    """Groups regression coverage for plugin checker tests for test bundled reports."""
    def test_check_all_bundled_plugins_json_output(self):
        """Protect check all bundled plugins json output behavior from regressions."""
        output = capture_stdout(lambda: main(["--all", "--json"]))

        data = json.loads(output)
        self.assertTrue(data["ok"])
        self.assertGreater(data["checked"], 10)
        self.assertTrue(any(item["entry"] == "http.webfin" for item in data["plugins"]))

    def test_check_bundled_plugins_report_shape(self):
        """Protect check bundled plugins report shape behavior from regressions."""
        report = check_bundled_plugins()

        self.assertTrue(report["ok"])
        self.assertEqual(report["plugin"], "bywaf.plugins")
        self.assertEqual(report["errors"], [])

    def test_check_bundled_plugins_strict_inference_passes(self):
        """Protect check bundled plugins strict inference passes behavior from regressions."""
        report = check_bundled_plugins(strict_inference=True)

        self.assertTrue(report["ok"])
        self.assertEqual(report["errors"], [])

    def test_check_bundled_plugins_registers_manifest_event_schemas_before_topic_warning(self):
        """Protect check bundled plugins registers manifest event schemas before topic warning behavior from regressions."""
        report = check_bundled_plugins()

        by_entry = {item["entry"]: item for item in report["plugins"]}
        self.assertNotIn("web.fingerprint", by_entry["http.webfin"]["unregistered_declared_emits"])
        self.assertNotIn("http.headers", by_entry["http.headers"]["unregistered_declared_emits"])


if __name__ == "__main__":
    unittest.main()
