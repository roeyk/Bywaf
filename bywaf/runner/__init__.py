"""Runner package compatibility exports.

Provides the stable `bywaf.runner` import surface while implementation moves
into cohesive runner modules: core, background, context, stages, jobs,
at_files, plans, and runtime_events.
"""

from .at_files import AtFileExpansion
from .at_files import attach_at_file_artifact
from .at_files import at_file_expanders
from .at_files import expand_at_file_arg
from .at_files import expand_at_file_args
from .at_files import parse_at_file_token
from .at_files import publish_at_file_expansion
from .background import run_attached_pipeline_job
from .background import run_background_job
from .core import add_runner_arguments
from .context import StageRun
from .context import build_context
from .context import effective_run_vars
from .context import ensure_run_var_snapshot
from .context import is_management_pipeline
from .context import new_run_id
from .context import prepare_stage_runs
from .context import select_input_events
from .core import Runner
from .jobs import JobLifecycle
from .jobs import should_run_stage_processes
from .plans import format_plan_report
from .plans import handle_plan_if_needed
from .plans import maybe_apply_plan_repair
from .plans import publish_plan_decision
from .plans import publish_plan_repair
from .plans import publish_plan_requested
from .plans import publish_policy_evaluated
from .runtime_events import attach_cursor_event_id
from .runtime_events import pipeline_exists
from .runtime_events import publish_note_if_present
from .runtime_events import publish_runtime_name
from .runtime_events import publish_variable_expansion
from .stages import StageResult
from .stages import execute_stage
from .stages import normalize_valued_option_args
from .stages import pipeline_visible_stage_events
from .stages import publish_command_run_arguments
from .stages import publish_command_run_lifecycle
from .stages import redact_commandlet_args
from .stages import run_stage_process
from .stages import secret_arg_metadata
from .stages import split_option_arg

# Public runner facade.  Command execution spans several focused modules, but
# commandlets, tests, and CLI startup code should continue importing runner
# primitives from this package root.
__all__ = [
    "AtFileExpansion",
    "JobLifecycle",
    "Runner",
    "StageResult",
    "StageRun",
    "add_runner_arguments",
    "attach_at_file_artifact",
    "attach_cursor_event_id",
    "at_file_expanders",
    "build_context",
    "effective_run_vars",
    "ensure_run_var_snapshot",
    "execute_stage",
    "expand_at_file_arg",
    "expand_at_file_args",
    "format_plan_report",
    "handle_plan_if_needed",
    "is_management_pipeline",
    "maybe_apply_plan_repair",
    "new_run_id",
    "normalize_valued_option_args",
    "parse_at_file_token",
    "pipeline_exists",
    "pipeline_visible_stage_events",
    "prepare_stage_runs",
    "publish_at_file_expansion",
    "publish_command_run_arguments",
    "publish_command_run_lifecycle",
    "publish_note_if_present",
    "publish_plan_decision",
    "publish_plan_repair",
    "publish_plan_requested",
    "publish_policy_evaluated",
    "publish_runtime_name",
    "publish_variable_expansion",
    "redact_commandlet_args",
    "run_attached_pipeline_job",
    "run_background_job",
    "run_stage_process",
    "secret_arg_metadata",
    "select_input_events",
    "should_run_stage_processes",
    "split_option_arg",
]
