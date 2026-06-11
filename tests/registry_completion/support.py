# ruff: noqa: F401
"""Shared helpers for registry and completion tests."""

from pathlib import Path
import importlib
import os
import tempfile
import unittest
from types import ModuleType
from unittest.mock import patch

from bywaf.completion import (
    COMPLETION_SELECT_KEY_VAR,
    COMPLETION_WASD_SELECTION_VAR,
    Completer,
    PromptToolkitCompleter,
    cancel_completion_menu,
    common_completion_prefix,
    completion_results,
    completion_select_key,
    completion_select_key_display,
    wasd_selection_enabled,
    configure_readline_delimiters,
    display_label,
    prompt_secret_mode,
    secret_input_bottom_toolbar,
    secret_input_mode,
    should_print_completion_menu,
    tokens_after_last_pipe,
)
from bywaf.db import EventStore
from bywaf.event.schemas import EventSchema, FieldSchema
from bywaf.registry import (
    PluginManifestTrust,
    PluginRegistry,
    PluginTrustError,
    PluginTrustPolicy,
    canonical_manifest_bytes,
    load_filesystem_plugin_package,
    load_package_manifest,
    load_plugin,
    parse_package_plugin_aliases,
    parse_package_plugin_config,
    parse_plugin_config,
    parse_plugin_manifest,
    parse_plugin_manifest_data,
    plugin_manifest_digest,
)
from bywaf.secret.input import SECRET_BLOCK_VALUE, PromptSecretInputState, PromptSecretSpan, open_secret_assignment_name
from bywaf.specs import ArgumentSpec, CommandSpec, CompletionSpec, OptionSpec, TriggerSpec
from bywaf.tools.plugin_manifest import manifest_from_plugins


class FakePromptBuffer:
    def __init__(self, text: str, cursor_position: int) -> None:
        self.text = text
        self.cursor_position = cursor_position

    def delete_before_cursor(self, count: int = 1) -> None:
        start = max(0, self.cursor_position - count)
        self.text = self.text[:start] + self.text[self.cursor_position :]
        self.cursor_position = start

    def delete(self, count: int = 1) -> None:
        end = min(len(self.text), self.cursor_position + count)
        self.text = self.text[: self.cursor_position] + self.text[end:]


class FakePromptOutput:
    def __init__(self) -> None:
        self.shown = False

    def show_cursor(self) -> None:
        self.shown = True


class FakePromptApp:
    def __init__(self) -> None:
        self.output = FakePromptOutput()
        self.invalidated = False

    def invalidate(self) -> None:
        self.invalidated = True


def write_trigger_plugin(plugin_dir: Path) -> None:
    (plugin_dir / "plugin.py").write_text(
        "from bywaf.plugin import CommandSpec, TriggerSpec\n"
        "class Example:\n"
        "    spec = CommandSpec('example', 'example plugin')\n"
        "    def run(self, context, args, input_events):\n"
        "        yield {'ok': True}\n"
        "def plugin():\n"
        "    return Example()\n"
        "def triggers():\n"
        "    return (TriggerSpec(\n"
        "        name='example-trigger',\n"
        "        topic='example.event',\n"
        "        action_command='example',\n"
        "        description='ON example.event DO example',\n"
        "        action_mode='background',\n"
        "        payload_equals=(('kind', 'demo'),),\n"
        "    ),)\n"
    )


def write_trigger_manifest(plugin_dir: Path, *, action_command: str = "example") -> None:
    (plugin_dir / "bywaf.plugin.toml").write_text(
        "[plugin]\n"
        'version = "0.1.0"\n\n'
        "[[commandlets]]\n"
        'name = "example"\n'
        "capabilities = []\n\n"
        "[[triggers]]\n"
        'name = "example-trigger"\n'
        'topic = "example.event"\n'
        f'action_command = "{action_command}"\n'
        'description = "ON example.event DO example"\n'
        'action_mode = "background"\n'
        'payload_equals = { kind = "demo" }\n'
    )
