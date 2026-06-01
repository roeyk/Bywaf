"""Tests for the external LLM plugin-evaluation harness."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_llm_plugin_eval import REDACTED_VALUE, sanitize_json, write_json


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

    def test_write_json_persists_non_sensitive_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "payload.json")
            write_json(path, {"text": "safe"})

            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
            self.assertEqual(data["text"], "safe")


if __name__ == "__main__":
    unittest.main()
