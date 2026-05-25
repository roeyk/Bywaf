"""Shared user-facing command-name constants.

Provides command spellings used across dispatch, completion, redaction, and
input helpers without depending on the REPL package.

Used by:
- REPL command dispatch and completion.
- secret input/redaction helpers that need command-aware parsing.
"""

from __future__ import annotations

SET_COMMAND = "set"
SETG_COMMAND = "setg"
VARIABLE_COMMANDS = frozenset((SET_COMMAND, SETG_COMMAND))

PROJECT_COMMAND = "project"
PROJECT_ALIAS_COMMAND = "proj"
PROJECT_ARCHIVE = "archive"
PROJECT_EXPORT = "export"
PROJECT_INFO = "info"
PROJECT_LIST = "list"
PROJECT_NEW = "new"
PROJECT_USE = "use"
PROJECT_ACTIONS = (PROJECT_ARCHIVE, PROJECT_EXPORT, PROJECT_INFO, PROJECT_LIST, PROJECT_NEW, PROJECT_USE)
