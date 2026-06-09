"""Tests for public plugin selector parsing helpers."""

from __future__ import annotations

import unittest

from bywaf.plugin import parse_key_value_token, parse_key_value_tokens, require_exactly_one_selector


class PluginSelectorApiTests(unittest.TestCase):
    def test_parse_key_value_tokens_supports_final_text_selector(self) -> None:
        selectors = parse_key_value_tokens(
            ["step=1", "text=validated", "manually"],
            allowed_keys={"step", "text"},
            command="example",
            text_keys={"text"},
        )

        self.assertEqual(selectors, {"step": "1", "text": "validated manually"})

    def test_parse_key_value_tokens_rejects_unknown_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown example selector: other"):
            parse_key_value_tokens(["other=value"], allowed_keys={"step"}, command="example")

    def test_parse_key_value_token_requires_key_value_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid example selector"):
            parse_key_value_token("missing-value", command="example")

    def test_require_exactly_one_selector_returns_present_key(self) -> None:
        self.assertEqual(
            require_exactly_one_selector({"pipeline": "7"}, ("job", "pipeline", "step"), command="example"),
            "pipeline",
        )

    def test_require_exactly_one_selector_rejects_ambiguous_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires exactly one"):
            require_exactly_one_selector({"job": "1", "step": "2"}, ("job", "pipeline", "step"), command="example")


if __name__ == "__main__":
    unittest.main()
