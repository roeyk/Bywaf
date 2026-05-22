"""Public completion-core facade.

Provides stable imports for the readline/prompt-toolkit completion adapter
while the implementation lives in focused helper modules.
"""

from __future__ import annotations

from .constants import BINARY_OPTION_NAMES, FRAMEWORK_OPTION_COMPLETIONS, option_is_binary
from .engine import CoreCompleter
from .providers import bundle_candidates, history_candidates, key_candidates
from .resources import (
    DEFAULT_SETTINGS,
    complete_at_file_prefix,
    complete_resource_value,
    is_explicit_path,
    preserve_explicit_prefix,
    resource_candidates,
)
from .runtime import runtime_completion_target
from .tokens import positional_index, tokens_after_last_pipe
from .variables import variable_reference_candidates

__all__ = [
    "BINARY_OPTION_NAMES",
    "DEFAULT_SETTINGS",
    "FRAMEWORK_OPTION_COMPLETIONS",
    "CoreCompleter",
    "bundle_candidates",
    "complete_at_file_prefix",
    "complete_resource_value",
    "history_candidates",
    "is_explicit_path",
    "key_candidates",
    "option_is_binary",
    "positional_index",
    "preserve_explicit_prefix",
    "resource_candidates",
    "runtime_completion_target",
    "tokens_after_last_pipe",
    "variable_reference_candidates",
]
