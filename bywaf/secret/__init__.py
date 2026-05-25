"""Secret storage, redaction, and prompt-input helpers.

Provides the package namespace for in-memory secret handling and interactive
secret-entry support.

Used by:
- REPL and completion: collect masked values and preserve redacted commands.
- runner and plugins: resolve secret references at execution time."""

from .input import (
    SECRET_BLOCK_VALUE,
    PromptSecretInputState,
    PromptSecretSpan,
    open_secret_assignment_name,
    prompt_secret_key_bindings,
)
from .store import (
    REDACTED_VALUE,
    SECRET_REF_PREFIX,
    InMemorySecretStore,
    RedactedSecret,
    RedactionResult,
    SecretFingerprint,
    SecretRef,
    load_or_create_fingerprint_key,
    redact_command_text,
)

__all__ = [
    "InMemorySecretStore",
    "PromptSecretInputState",
    "PromptSecretSpan",
    "REDACTED_VALUE",
    "SECRET_BLOCK_VALUE",
    "SECRET_REF_PREFIX",
    "RedactedSecret",
    "RedactionResult",
    "SecretFingerprint",
    "SecretRef",
    "load_or_create_fingerprint_key",
    "open_secret_assignment_name",
    "prompt_secret_key_bindings",
    "redact_command_text",
]
