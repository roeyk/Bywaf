# ruff: noqa: F401
"""Shared helpers for config/plugin tests."""

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from bywaf.artifacts import artifact_store_for_db
from bywaf.config import Settings, default_settings
from bywaf.db import EventStore
from bywaf.event.schema_objects import OpenPort
from bywaf.messages import Host, Progress
from bywaf.plugin import CommandContext, CommandletBase, argument, commandlet, format_table, option
from bywaf.plugin.process import normalize_argv
from bywaf.registry import PluginRegistry
from bywaf.runner import redact_commandlet_args
from bywaf.runner.context import effective_run_vars
from bywaf.secret.store import InMemorySecretStore
from bywaf.specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec
from bywaf.varstore import ScopedVarStore, VarStore
