"""Configuration defaults and canonical config helpers.

Provides the public `bywaf.config` import surface while keeping settings and
canonicalization code in focused modules.

Used by:
- CLI, REPL, and API startup: resolve default paths and runtime settings.
- config tooling: normalize and persist variable configuration."""

from .canonical import canonical_config_bytes, canonical_config_value, config_digest
from .settings import Settings, default_settings

__all__ = [
    "Settings",
    "canonical_config_bytes",
    "canonical_config_value",
    "config_digest",
    "default_settings",
]
