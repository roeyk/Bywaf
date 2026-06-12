"""Public commandlet authoring facade.

Provides the internal `bywaf.plugin.command` package surface for commandlet
protocols, base classes, decorators, and manifest-backed adapters.

Used by:
- `bywaf.plugin`: re-exports plugin-authoring names from this module.
- bundled and external plugins: import commandlet authoring helpers directly or
  through `bywaf.plugin`.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
"""

from __future__ import annotations

from .base import Commandlet, CommandletBase, normalize_completion
from .decorators import argument, commandlet, option
from .manifest import FunctionCommandlet, ManifestArgumentParser, ManifestCommandlet, RunConfig
from .specs import (
    format_table as format_table,
    kv_args_to_options,
    manifest_args_from_toml,
    manifest_name_for_function,
    manifest_option_cast,
    manifest_option_default,
    manifest_path_for_function,
    option_dest,
    parse_manifest_bool,
    spec_from_manifest,
    split_var_values,
)

__all__ = [
    "Commandlet",
    "CommandletBase",
    "FunctionCommandlet",
    "ManifestArgumentParser",
    "ManifestCommandlet",
    "RunConfig",
    "argument",
    "commandlet",
    "format_table",
    "kv_args_to_options",
    "manifest_args_from_toml",
    "manifest_name_for_function",
    "manifest_option_cast",
    "manifest_option_default",
    "manifest_path_for_function",
    "normalize_completion",
    "option",
    "option_dest",
    "parse_manifest_bool",
    "spec_from_manifest",
    "split_var_values",
]
