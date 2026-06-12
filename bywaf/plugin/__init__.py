"""Public plugin API facade.

Provides the stable `bywaf.plugin` import surface for command contexts,
commandlet base types, decorator helpers, capability helpers, and common specs.

Used by:
- bundled and external plugins: import the public plugin-authoring API.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- registry and runner: type and invoke commandlets through stable names."""

from __future__ import annotations

from .capabilities import (
    capability_declared,
    database_action_allowed,
    database_action_for_capability,
    db_actions_for_caps,
    framework_request_capability,
    request_capability_map,
    request_prefix_caps,
    implied_capabilities,
)
from .command import (
    Commandlet,
    CommandletBase,
    ManifestCommandlet,
    RunConfig,
    argument,
    commandlet,
    format_table,
    manifest_args_from_toml,
    normalize_completion,
    option,
    spec_from_manifest,
    split_var_values,
)
from .context import (
    CommandContext,
    command_run_id,
    emit_alert,
)
from .pipeline import (
    ContextPipeline,
    PipelineStop,
)
from .parsing import kv_to_args, parse_bool, reject_option_equals
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
from .selectors import (
    parse_kv,
    parse_kvs,
    require_one_selector,
)
from .process import (
    ContextProcess,
    ProcessChunk,
    ProcessResult,
    audit_process_env,
    check_argv_for_secrets,
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
    "ContextPipeline",
    "ContextRender",
    "ContextSecrets",
    "ContextSignals",
    "ManifestCommandlet",
    "OptionSpec",
    "PlanItem",
    "PlanRepair",
    "PlanReport",
    "ProcessChunk",
    "ProcessResult",
    "PipelineStop",
    "RunConfig",
    "TriggerSpec",
    "argument",
    "artifact_event_payload",
    "audit_process_env",
    "capability_declared",
    "check_argv_for_secrets",
    "command_run_id",
    "commandlet",
    "database_action_allowed",
    "database_action_for_capability",
    "db_actions_for_caps",
    "emit_alert",
    "format_table",
    "framework_request_capability",
    "request_capability_map",
    "request_prefix_caps",
    "implied_capabilities",
    "kv_to_args",
    "leaked_secret_arguments",
    "manifest_args_from_toml",
    "normalize_argv",
    "normalize_completion",
    "option",
    "parse_bool",
    "parse_kv",
    "parse_kvs",
    "popen_process_argv",
    "progress_float_var",
    "progress_payload",
    "progress_percent",
    "redact_process_argv",
    "reject_option_equals",
    "require_one_selector",
    "run_process_argv",
    "should_emit_progress",
    "signal_applies_to_context",
    "spec_from_manifest",
    "split_var_values",
    "timeout_deadline",
    "timeout_expired",
]
