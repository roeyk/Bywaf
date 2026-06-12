# ruff: noqa: F401,F811
"""Shared helpers for storage runner tests.

Coverage focus: shared fixtures and test doubles for storage runner tests.
"""

from pathlib import Path
import contextlib
import io
import json
import os
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from bywaf.app import ShellState, make_runner, parse_save_spec, process_framework_requests
from bywaf.artifacts import artifact_db_path, artifact_store_for_db
from bywaf.command.parser import parse_invocation, parse_pipeline
from bywaf.db import EventStore, Subscription, database_appears_encrypted, sqlcipher_available
from bywaf.plugin import CommandContext
from bywaf.plugins.discovery.hostscanner import HostScanner, expand_targets
from bywaf.plugins.network.nmap_backend import NmapPort
from bywaf.plugins.network.portscanner import PortScanner
from bywaf.plugins.runtime.artifact import select_artifacts
from bywaf.plugins.runtime.audit.inventory import capability_inventory_row
from bywaf.plugins.runtime.watchdog import Watchdog
from bywaf.plugins.storage.db import encrypt_active_database
from bywaf.repl.shell import dispatch_repl_line
from bywaf.runner import expand_at_file_arg, prepare_stage_runs, run_background_job, should_run_stage_processes
from bywaf.specs import CommandSpec
from bywaf.varstore import VarStore


class StopPipelinePlugin:
    """Test double used by this module's regression cases."""
    spec = CommandSpec(
        "stop_pipeline",
        "stop the current pipeline",
        capabilities=("framework.pipeline.control",),
    )

    def run(self, context, args, input_events):
        """Test helper for run."""
        del args, input_events
        context.pipeline.stop("nothing useful downstream")
        return ()


class StopPipelineWithoutCapabilityPlugin:
    """Test double used by this module's regression cases."""
    spec = CommandSpec("stop_pipeline_undeclared", "stop the current pipeline without declaring control")

    def run(self, context, args, input_events):
        """Test helper for run."""
        del args, input_events
        context.pipeline.stop("undeclared")
        return ()


class DownstreamMarkerPlugin:
    """Test double used by this module's regression cases."""
    spec = CommandSpec(
        "downstream_marker",
        "mark downstream execution",
        emits=("downstream.marker",),
    )

    def run(self, context, args, input_events):
        """Test helper for run."""
        del context, args, input_events
        yield {"ran": True}


class InspectPipelineApiPlugin:
    """Test double used by this module's regression cases."""
    spec = CommandSpec(
        "inspect_pipeline_api",
        "inspect the plugin-facing pipeline API",
        emits=("pipeline.api.inspected",),
    )

    def run(self, context, args, input_events):
        """Test helper for run."""
        del args, input_events
        public_names = sorted(name for name in dir(context.pipeline) if not name.startswith("_"))
        yield {
            "public": public_names,
            "has_context": hasattr(context.pipeline, "context"),
            "has_downstream": hasattr(context.pipeline, "downstream"),
            "has_next_commandlet": hasattr(context.pipeline, "next_commandlet"),
            "has_position": hasattr(context.pipeline, "position"),
            "has_stage_count": hasattr(context.pipeline, "stage_count"),
            "has_stages": hasattr(context.pipeline, "stages"),
        }


class FakeHostResult:
    """Test double used by this module's regression cases."""
    def state(self):
        """Test helper for state."""
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    """Test double used by this module's regression cases."""
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    """Test double used by this module's regression cases."""
    PortScanner = FakePortScanner
