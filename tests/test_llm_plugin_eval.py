"""Tests for the external LLM plugin-evaluation harness."""

from __future__ import annotations

import json
import unittest

from scripts.run_llm_plugin_eval import REDACTED_VALUE, response_summary, sanitize_json


class LlmPluginEvalTests(unittest.TestCase):
    def test_sanitize_json_redacts_nested_sensitive_keys(self):
        payload = {
            "id": "response-1",
            "api_key": "secret-key",
            "headers": {"Authorization": "Bearer token", "content-type": "application/json"},
            "choices": [{"message": {"content": "ok", "session-token": "secret-token"}}],
        }

        redacted = sanitize_json(payload)

        self.assertEqual(redacted["api_key"], REDACTED_VALUE)
        self.assertEqual(redacted["headers"]["Authorization"], REDACTED_VALUE)
        self.assertEqual(redacted["choices"][0]["message"]["session-token"], REDACTED_VALUE)
        self.assertEqual(redacted["choices"][0]["message"]["content"], "ok")

    def test_response_summary_contains_only_shape_and_text_length(self):
        response = {"id": "response-1", "choices": [{"message": {"content": "safe text"}}]}

        summary = response_summary("openai", response)

        text = json.dumps(summary)
        self.assertEqual(summary["top_level_keys"], ["choices", "id"])
        self.assertEqual(summary["text_length"], len("safe text"))
        self.assertNotIn("safe text", text)


if __name__ == "__main__":
    unittest.main()
