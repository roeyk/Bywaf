"""Public plugin API facade.

Provides the stable `bywaf.plugin` import surface for command contexts,
commandlet base types, decorator helpers, capability helpers, and common specs.

Used by:
- bundled and external plugins: import the public plugin-authoring API.
- registry and runner: type and invoke commandlets through stable names."""

from __future__ import annotations

from .capabilities import (
    capability_declared,
    framework_request_capability,
    framework_request_capability_map,
    framework_request_prefix_capabilities,
    implied_capabilities,
)
from .commands import (
    Commandlet,
    CommandletBase,
    argument,
    commandlet,
    format_table,
    normalize_completion,
    option,
    split_var_values,
)
from .context import (
    CommandContext,
    command_run_id,
    emit_alert,
)
from .services import (
    CompletionContext,
    ContextArtifacts,
    ContextEvents,
    ContextRender,
    ContextSecrets,
    ContextSignals,
    artifact_event_payload,
    progress_float_var,
    progress_payload,
    progress_percent,
    should_emit_progress,
    signal_applies_to_context,
)
from .process import (
    ContextProcess,
    ProcessChunk,
    ProcessResult,
    audit_process_env,
    check_process_argv_for_secrets,
    leaked_secret_arguments,
    normalize_argv,
    popen_process_argv,
    redact_process_argv,
    run_process_argv,
    timeout_deadline,
    timeout_expired,
)
from ..specs import (
    ArgumentSpec,
    CommandSpec,
    CompletionSpec,
    OptionSpec,
    PlanItem,
    PlanRepair,
    PlanReport,
    TriggerSpec,
)

# This package is the public plugin-authoring API.  Keep plugin-facing imports
# here even when the implementation lives in submodules, so external plugins can
# depend on `from bywaf.plugin import CommandletBase, commandlet, option, ...`
# without tracking framework internals.
__all__ = [
    "ArgumentSpec",
    "CommandContext",
    "CommandSpec",
    "Commandlet",
    "CommandletBase",
    "CompletionContext",
    "CompletionSpec",
    "ContextArtifacts",
    "ContextEvents",
    "ContextProcess",
    "ContextRender",
    "ContextSecrets",
    "ContextSignals",
    "OptionSpec",
    "PlanItem",
    "PlanRepair",
    "PlanReport",
    "ProcessChunk",
    "ProcessResult",
    "TriggerSpec",
    "argument",
    "artifact_event_payload",
    "audit_process_env",
    "capability_declared",
    "check_process_argv_for_secrets",
    "command_run_id",
    "commandlet",
    "emit_alert",
    "format_table",
    "framework_request_capability",
    "framework_request_capability_map",
    "framework_request_prefix_capabilities",
    "implied_capabilities",
    "leaked_secret_arguments",
    "normalize_argv",
    "normalize_completion",
    "option",
    "popen_process_argv",
    "progress_float_var",
    "progress_payload",
    "progress_percent",
    "redact_process_argv",
    "run_process_argv",
    "should_emit_progress",
    "signal_applies_to_context",
    "split_var_values",
    "timeout_deadline",
    "timeout_expired",
]
