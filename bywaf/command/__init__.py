"""Command parsing and command-name helpers.

Provides the package namespace for user-facing command constants and pipeline
parsing utilities.

Used by:
- runner and REPL: parse commandlet pipelines and built-in command names.
- completion and tests: keep command spelling and parser behavior consistent."""

from .names import (
    PROJECT_ACTIONS,
    PROJECT_ALIAS_COMMAND,
    PROJECT_ARCHIVE,
    PROJECT_EXPORT,
    PROJECT_INFO,
    PROJECT_LIST,
    PROJECT_NEW,
    PROJECT_USE,
    PROJECT_COMMAND,
    SET_COMMAND,
    SETG_COMMAND,
    VARIABLE_COMMANDS,
)
from .parser import CommandInvocation, Pipeline, parse_invocation, parse_pipeline

__all__ = [
    "CommandInvocation",
    "PROJECT_ACTIONS",
    "PROJECT_ALIAS_COMMAND",
    "PROJECT_ARCHIVE",
    "PROJECT_COMMAND",
    "PROJECT_EXPORT",
    "PROJECT_INFO",
    "PROJECT_LIST",
    "PROJECT_NEW",
    "PROJECT_USE",
    "Pipeline",
    "SET_COMMAND",
    "SETG_COMMAND",
    "VARIABLE_COMMANDS",
    "parse_invocation",
    "parse_pipeline",
]
