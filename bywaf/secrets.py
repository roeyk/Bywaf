"""Secret redaction and audit fingerprint helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .config import default_settings

FINGERPRINT_ALGORITHM = "hmac-sha256"
FINGERPRINT_HEX_CHARS = 24
REDACTED_VALUE = "<redacted>"
SECRET_REF_PREFIX = "$__secret_"
SECRET_NAME_HINTS = frozenset(
    {
        "api-key",
        "api_key",
        "authorization",
        "cookie",
        "pass",
        "passwd",
        "password",
        "pw",
        "secret",
        "token",
    }
)


@dataclass(frozen=True, slots=True)
class SecretFingerprint:
    """Audit-safe correlation fingerprint for a secret value."""

    algorithm: str
    value: str

    def format(self) -> str:
        """Return the display/storage form."""
        return f"{self.algorithm}:{self.value}"


@dataclass(frozen=True, slots=True)
class RedactedSecret:
    """One redacted secret field found in command text."""

    name: str
    fingerprint: SecretFingerprint
    source: str = "inline"


@dataclass(frozen=True, slots=True)
class SecretRef:
    """In-memory reference to a secret value that must not be persisted."""

    ref: str
    name: str
    fingerprint: SecretFingerprint
    source: str = "vars"


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Command text after secret removal plus correlation metadata."""

    command: str
    secrets: tuple[RedactedSecret, ...] = field(default_factory=tuple)


@dataclass(slots=True)
class InMemorySecretStore:
    """REPL-local secret storage keyed by opaque references.

    The variable store and audit history only receive the reference and a
    fingerprint; the plaintext secret remains in this process.
    """

    values: dict[str, str] = field(default_factory=dict)
    refs: dict[str, SecretRef] = field(default_factory=dict)

    def put(self, name: str, value: str, *, key: bytes, source: str = "vars") -> SecretRef:
        """Store a secret value and return an opaque reference for varstore use."""
        ref = f"{SECRET_REF_PREFIX}{os.urandom(8).hex()}"
        secret_ref = SecretRef(ref=ref, name=name, fingerprint=fingerprint_secret(value, key), source=source)
        self.remember(secret_ref, value)
        return secret_ref

    def remember(self, secret_ref: SecretRef, value: str) -> None:
        """Remember an existing reference loaded from persistent storage."""
        self.values[secret_ref.ref] = value
        self.refs[secret_ref.ref] = secret_ref

    def get(self, ref: str) -> str | None:
        """Return plaintext for trusted framework code that explicitly resolves it."""
        return self.values.get(ref)

    def metadata(self, ref: str) -> SecretRef | None:
        """Return redaction metadata for display/audit output."""
        return self.refs.get(ref)

    def is_ref(self, value: str | None) -> bool:
        """Return whether a varstore value is an in-memory secret reference."""
        return bool(value and value.startswith(SECRET_REF_PREFIX) and value in self.refs)


def load_or_create_fingerprint_key(path: Path | None = None) -> bytes:
    """Load the local HMAC key used for audit-only secret fingerprints."""
    key_path = path or default_settings().secret_fingerprint_key
    if key_path.exists():
        return key_path.read_bytes()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    with key_path.open("xb") as handle:
        handle.write(key)
    os.chmod(key_path, 0o600)
    return key


def fingerprint_secret(secret: str, key: bytes) -> SecretFingerprint:
    """Return a truncated keyed fingerprint for correlation, not recovery."""
    digest = hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()
    return SecretFingerprint(FINGERPRINT_ALGORITHM, digest[:FINGERPRINT_HEX_CHARS])


def is_secret_name(name: str, declared: set[str] | frozenset[str] = frozenset()) -> bool:
    """Return whether a command option name should be treated as secret."""
    normalized = name.strip().lower().replace("_", "-")
    declared_normalized = {item.strip().lower().replace("_", "-") for item in declared}
    return normalized in declared_normalized or normalized in SECRET_NAME_HINTS


def redact_command_text(command: str, *, key: bytes, secret_names: set[str] | frozenset[str] = frozenset()) -> RedactionResult:
    """Redact `name=value` secret assignments in command text.

    This is deliberately conservative and intended for history/audit text. The
    interactive editor should pass redacted tokens directly once integrated.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return RedactionResult(command)

    redacted_tokens: list[str] = []
    secrets: list[RedactedSecret] = []
    for token in tokens:
        if "=" not in token:
            redacted_tokens.append(token)
            continue
        name, value = token.split("=", 1)
        if value and is_secret_name(name, secret_names):
            redacted_tokens.append(f"{name}={REDACTED_VALUE}")
            secrets.append(RedactedSecret(name=name, fingerprint=fingerprint_secret(value, key)))
        else:
            redacted_tokens.append(token)
    return RedactionResult(" ".join(quote_redacted_token(token) for token in redacted_tokens), tuple(secrets))


def quote_redacted_token(token: str) -> str:
    """Quote normal shell tokens while keeping `<redacted>` readable."""
    if token.endswith(f"={REDACTED_VALUE}"):
        return token
    return shlex.quote(token)
