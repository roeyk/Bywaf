# ruff: noqa: F401
"""Shared helpers for resources, history, and config tests.

Coverage focus: shared fixtures and test doubles for resources history config tests.
"""

from pathlib import Path
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from bywaf.app import (
    ShellState,
    dispatch_repl_line,
    format_history_entry,
    line_has_continuation,
    load_history,
    make_runner,
    record_command_history,
    remove_line_continuation,
    resolve_resource_path,
    run_script,
    save_history,
    script_commands,
    set_prompt_pattern,
    split_command_sequence,
    strip_inline_comment,
)
from bywaf.plugins.network.nmap_backend import NmapScanError, NmapUnavailableError
from bywaf.repl import redact_history_command
from bywaf.repl.shell import apply_startup_preferences
from bywaf.style import subject_style


def write_simple_external_plugin(root: Path, name: str) -> Path:
    """Test helper for write simple external plugin."""
    plugin_dir = root / name
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        f"class Example:\n"
        f"    spec = CommandSpec('{name}', '{name} plugin', emits=('{name}.done',))\n"
        "    def run(self, context, args, input_events):\n"
        "        del context, args, input_events\n"
        "        yield {'ok': True}\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        f'name = "{name}"\n'
        "capabilities = []\n"
    )
    return plugin_dir


def write_console_external_plugin(root: Path, *, declare_output: bool) -> Path:
    """Test helper for write console external plugin."""
    plugin_dir = root / "external_console"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        f"CAPABILITIES = {('framework.console.output',) if declare_output else ()!r}\n"
        "class Example:\n"
        "    spec = CommandSpec('external_console', 'external console plugin', capabilities=CAPABILITIES)\n"
        "    def run(self, context, args, input_events):\n"
        "        del args, input_events\n"
        "        context.output('hello from external')\n"
        "        return ()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    capabilities = '["framework.console.output"]' if declare_output else "[]"
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "external_console"\n'
        f"capabilities = {capabilities}\n"
    )
    return plugin_dir


def write_external_plugin_with_vars(root: Path) -> Path:
    plugin_dir = root / "vars"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "from bywaf.specs import OptionSpec\n"
        "class Example:\n"
        "    spec = CommandSpec(\n"
        "        'example',\n"
        "        'example plugin',\n"
        "        options=(OptionSpec('first', 'first'), OptionSpec('second', 'second'), OptionSpec('token', 'token', secret=True)),\n"
        "        provider_variables=('proxy',),\n"
        "    )\n"
        "    def run(self, context, args, input_events):\n"
        "        del context, args, input_events\n"
        "        return ()\n"
        "def plugin():\n"
        "    return Example()\n"
    )
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[[commandlets]]\n"
        'name = "example"\n'
        'secret_options = ["token"]\n'
        'provider_variables = ["proxy"]\n'
        "capabilities = []\n"
    )
    (plugin_dir / "defaults.toml").write_text("[defaults]\nhidden = true\n")
    return plugin_dir


def write_multi_external_plugin(root: Path, *, default_commandlet: str | None = None) -> Path:
    plugin_dir = root / "multi"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec\n"
        "class First:\n"
        "    spec = CommandSpec('first', 'first plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        return ()\n"
        "class Second:\n"
        "    spec = CommandSpec('second', 'second plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        return ()\n"
        "def plugins():\n"
        "    return (First(), Second())\n"
    )
    plugin_table = "[plugin]\n" + (f'default_commandlet = "{default_commandlet}"\n\n' if default_commandlet else "\n")
    (plugin_dir / "bywaf.plugin.toml").write_text(
        plugin_table +
        "[[commandlets]]\n"
        'name = "first"\n'
        "capabilities = []\n\n"
        "[[commandlets]]\n"
        'name = "second"\n'
        "capabilities = []\n"
    )
    return plugin_dir


class FakeHostResult:
    """Test double used by this module's regression cases."""
    def state(self):
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
