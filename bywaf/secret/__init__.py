"""Secret storage, redaction, and prompt-input helpers.

Provides the package namespace for in-memory secret handling and interactive
secret-entry support.

Used by:
- REPL and completion: collect masked values and preserve redacted commands.
- runner and plugins: resolve secret references at execution time."""

from .input import (
    DEFAULT_SECRET_INPUT_MODE,
    SECRET_BLOCK_VALUE,
    SECRET_INPUT_MODES,
    SECRET_INPUT_MODE_VAR,
    PromptSecretInputState,
    PromptSecretSpan,
    effective_secret_input_mode,
    normalize_secret_input_mode,
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
    load_fingerprint_key,
    redact_command_text,
)

__all__ = [
    "InMemorySecretStore",
    "DEFAULT_SECRET_INPUT_MODE",
    "PromptSecretInputState",
    "PromptSecretSpan",
    "REDACTED_VALUE",
    "SECRET_BLOCK_VALUE",
    "SECRET_INPUT_MODES",
    "SECRET_INPUT_MODE_VAR",
    "SECRET_REF_PREFIX",
    "RedactedSecret",
    "RedactionResult",
    "SecretFingerprint",
    "SecretRef",
    "effective_secret_input_mode",
    "load_fingerprint_key",
    "normalize_secret_input_mode",
    "open_secret_assignment_name",
    "prompt_secret_key_bindings",
    "redact_command_text",
]
