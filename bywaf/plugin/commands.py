"""Public commandlet authoring facade.

Provides the stable `bywaf.plugin.commands` import surface for commandlet
protocols, base classes, decorators, and manifest-backed adapters.

Used by:
- `bywaf.plugin`: re-exports plugin-authoring names from this module.
- bundled and external plugins: import commandlet authoring helpers directly or
  through `bywaf.plugin`.
"""

from __future__ import annotations

from .command_base import Commandlet, CommandletBase, normalize_completion
from .command_decorators import argument, commandlet, option
from .command_manifest import FunctionCommandlet, ManifestArgumentParser, ManifestCommandlet, RunConfig
from .manifest_specs import (
    format_table as format_table,
    key_value_args_to_options,
    manifest_arguments_from_manifest,
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
    "key_value_args_to_options",
    "manifest_arguments_from_manifest",
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
