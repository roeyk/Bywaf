"""Subprocess execution helpers for external plugin tools.

Provides process launching, output capture, and result normalization for plugins
that wrap command-line binaries.

Used by:
- wrapper plugins such as nikto, eyewitness, and wireless scanners.

Public surface: re-exports the package API so callers can import the
subsystem without depending on internal module layout.
- tests: verify external command error and output handling."""


from .audit import audit_process_env as audit_process_env
from .audit import check_argv_for_secrets as check_argv_for_secrets
from .audit import leaked_secret_arguments as leaked_secret_arguments
from .audit import redact_known_secret_values as redact_known_secret_values
from .audit import redact_process_argv as redact_process_argv
from .context import ContextProcess as ContextProcess
from .exec import normalize_argv as normalize_argv
from .exec import popen_process_argv as popen_process_argv
from .exec import run_process_argv as run_process_argv
from .models import ProcessResult as ProcessResult
from .stream import (
    ProcessChunk as ProcessChunk,
    StreamProcessState as StreamProcessState,
    close_stream_process as close_stream_process,
    process_output_selector as process_output_selector,
    raise_if_stream_timeout as raise_if_stream_timeout,
    read_stream_chunk as read_stream_chunk,
    timeout_deadline as timeout_deadline,
    timeout_expired,  # noqa: F401 - re-exported from this module for plugin API compatibility.
)
