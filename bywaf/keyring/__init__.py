"""Public keyring facade.

Provides stable imports for key management commandlets, bundle signing, and
completion while implementation lives in focused keyring modules.

Used by:
- Bywaf application code and tests that import this public module surface.
"""

from __future__ import annotations

from .crypto import (
    crypto_ed25519_private_key,
    crypto_serialization,
    load_private_key,
    load_public_key,
    public_key_from_private,
    private_key_is_encrypted,
    public_key_fingerprint,
    serialize_private_key,
    serialize_public_key,
)
from .models import KEY_NAME_RE, SUPPORTED_ALGORITHM, KeyPaths, KeyRecord
from .operations import (
    export_public_key,
    generate_key,
    import_private_key,
    import_public_key,
    now_iso,
    sign_bytes,
    signing_key_names,
    signing_state_for_record,
    test_key,
    verification_key_names,
    verify_bytes,
)
from .permissions import (
    chmod_private_dir,
    write_private_file,
    write_private_permissions,
    write_public_file,
)
from .storage import (
    default_key_paths,
    ensure_key_dirs,
    escape_toml,
    key_by_name,
    key_filename,
    load_key_records,
    optional_path,
    record_from_dict,
    remove_key,
    save_key_records,
    upsert_key,
    validate_key_name,
)

# Keep keyring internals split by concern while preserving the original public
# import surface for runtime commandlets, bundle signing, and tests.
__all__ = [
    "KEY_NAME_RE",
    "SUPPORTED_ALGORITHM",
    "KeyPaths",
    "KeyRecord",
    "chmod_private_dir",
    "crypto_ed25519_private_key",
    "crypto_serialization",
    "default_key_paths",
    "ensure_key_dirs",
    "escape_toml",
    "export_public_key",
    "generate_key",
    "import_private_key",
    "import_public_key",
    "key_by_name",
    "key_filename",
    "load_key_records",
    "load_private_key",
    "load_public_key",
    "public_key_from_private",
    "now_iso",
    "optional_path",
    "private_key_is_encrypted",
    "public_key_fingerprint",
    "record_from_dict",
    "remove_key",
    "save_key_records",
    "serialize_private_key",
    "serialize_public_key",
    "sign_bytes",
    "signing_key_names",
    "signing_state_for_record",
    "test_key",
    "upsert_key",
    "validate_key_name",
    "verification_key_names",
    "verify_bytes",
    "write_private_file",
    "write_private_permissions",
    "write_public_file",
]
