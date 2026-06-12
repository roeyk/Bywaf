"""Tests for public plugin selector parsing helpers.

Coverage focus: config plugin selector api regression behavior.
"""

from __future__ import annotations

import unittest

from bywaf.plugin import kv_to_args, parse_bool, parse_kv, parse_kvs, reject_option_equals, require_one_selector


class PluginSelectorApiTests(unittest.TestCase):
    """Groups regression coverage for public plugin selector parsing helpers."""
    def test_parse_kvs_supports_final_text_selector(self) -> None:
        """Protect parse kvs supports final text selector behavior from regressions."""
        selectors = parse_kvs(
            ["step=1", "text=validated", "manually"],
            allowed_keys={"step", "text"},
            command="example",
            text_keys={"text"},
        )

        self.assertEqual(selectors, {"step": "1", "text": "validated manually"})

    def test_parse_kvs_rejects_unknown_keys(self) -> None:
        """Protect parse key/value selectors rejects unknown keys behavior from regressions."""
        with self.assertRaisesRegex(ValueError, "unknown example selector: other"):
            parse_kvs(["other=value"], allowed_keys={"step"}, command="example")

    def test_parse_kv_requires_key_value_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid example selector"):
            parse_kv("missing-value", command="example")

    def test_require_one_selector_returns_present_key(self) -> None:
        self.assertEqual(
            require_one_selector({"pipeline": "7"}, ("job", "pipeline", "step"), command="example"),
            "pipeline",
        )

    def test_require_one_selector_rejects_ambiguous_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires exactly one"):
            require_one_selector({"job": "1", "step": "2"}, ("job", "pipeline", "step"), command="example")

    def test_parse_bool_accepts_common_truthy_values(self) -> None:
        for value in (True, "1", "true", "yes", "on", " TRUE "):
            with self.subTest(value=value):
                self.assertTrue(parse_bool(value))

    def test_parse_bool_rejects_other_values(self) -> None:
        for value in (False, "0", "false", "no", "off", ""):
            with self.subTest(value=value):
                self.assertFalse(parse_bool(value))

    def test_kv_to_args_converts_declared_keys_only(self) -> None:
        self.assertEqual(
            kv_to_args(["target=example.test", "raw=a=b"], {"target"}),
            ["--target", "example.test", "raw=a=b"],
        )

    def test_reject_option_equals_rejects_declared_long_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "usage"):
            reject_option_equals(["--target=example.test"], {"target"}, usage="usage")


if __name__ == "__main__":
    unittest.main()
