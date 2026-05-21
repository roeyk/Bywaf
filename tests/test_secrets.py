"""Tests for secrets behavior.

Provides pytest coverage for the corresponding Bywaf subsystem and its public
or user-visible behavior.

Used by:
- pytest and CI: detect regressions in this subsystem.
- maintainers: document expected behavior through executable examples."""

from pathlib import Path
import tempfile
import unittest

from bywaf.secrets import (
    InMemorySecretStore,
    REDACTED_VALUE,
    SECRET_REF_PREFIX,
    fingerprint_secret,
    is_secret_name,
    load_or_create_fingerprint_key,
    redact_command_text,
)


class SecretTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_keyed(self):
        key = b"k" * 32
        self.assertEqual(fingerprint_secret("secret", key), fingerprint_secret("secret", key))
        self.assertNotEqual(fingerprint_secret("secret", key), fingerprint_secret("other", key))
        self.assertNotEqual(fingerprint_secret("secret", key), fingerprint_secret("secret", b"z" * 32))

    def test_load_or_create_fingerprint_key_writes_restrictive_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "secret.key")
            key = load_or_create_fingerprint_key(path)
            self.assertEqual(len(key), 32)
            self.assertEqual(load_or_create_fingerprint_key(path), key)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_is_secret_name_uses_declared_and_common_names(self):
        self.assertTrue(is_secret_name("password"))
        self.assertTrue(is_secret_name("api_key"))
        self.assertTrue(is_secret_name("custom", {"custom"}))
        self.assertFalse(is_secret_name("timeout"))

    def test_redact_command_text_replaces_secret_values_with_fingerprints(self):
        result = redact_command_text(
            "ssh_probe username=hello password='top secret' timeout=5",
            key=b"k" * 32,
        )
        self.assertEqual(result.command, f"ssh_probe username=hello password={REDACTED_VALUE} timeout=5")
        self.assertEqual(len(result.secrets), 1)
        self.assertEqual(result.secrets[0].name, "password")
        self.assertTrue(result.secrets[0].fingerprint.format().startswith("hmac-sha256:"))
        self.assertNotIn("top secret", result.command)

    def test_redact_command_text_uses_declared_secret_names(self):
        result = redact_command_text("cmd client-token=abc timeout=1", key=b"k" * 32, secret_names={"client-token"})
        self.assertEqual(result.command, f"cmd client-token={REDACTED_VALUE} timeout=1")
        self.assertEqual(result.secrets[0].name, "client-token")

    def test_in_memory_secret_store_returns_opaque_reference(self):
        store = InMemorySecretStore()
        ref = store.put("ssh_probe.password", "supersecret", key=b"k" * 32)
        self.assertTrue(ref.ref.startswith(SECRET_REF_PREFIX))
        self.assertEqual(store.get(ref.ref), "supersecret")
        self.assertEqual(store.metadata(ref.ref), ref)
        self.assertTrue(store.is_ref(ref.ref))
        self.assertNotIn("supersecret", ref.ref)

    def test_in_memory_secret_store_remembers_existing_reference(self):
        first = InMemorySecretStore()
        ref = first.put("ssh_probe.password", "supersecret", key=b"k" * 32)
        second = InMemorySecretStore()
        second.remember(ref, "supersecret")
        self.assertEqual(second.get(ref.ref), "supersecret")
        self.assertEqual(second.metadata(ref.ref), ref)


if __name__ == "__main__":
    unittest.main()
