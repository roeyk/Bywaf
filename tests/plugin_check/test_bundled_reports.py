"""Plugin checker tests for test bundled reports."""

import json
import unittest

from scripts.plugin_check import check_bundled_plugins, main
from tests.plugin_check_fixtures import capture_stdout


class TestBundledReportsTests(unittest.TestCase):
    def test_check_all_bundled_plugins_json_output(self):
        output = capture_stdout(lambda: main(["--all", "--json"]))

        data = json.loads(output)
        self.assertTrue(data["ok"])
        self.assertGreater(data["checked"], 10)
        self.assertTrue(any(item["entry"] == "http.webfin" for item in data["plugins"]))

    def test_check_bundled_plugins_report_shape(self):
        report = check_bundled_plugins()

        self.assertTrue(report["ok"])
        self.assertEqual(report["plugin"], "bywaf.plugins")
        self.assertEqual(report["errors"], [])

    def test_check_bundled_plugins_strict_inference_passes(self):
        report = check_bundled_plugins(strict_inference=True)

        self.assertTrue(report["ok"])
        self.assertEqual(report["errors"], [])


if __name__ == "__main__":
    unittest.main()
