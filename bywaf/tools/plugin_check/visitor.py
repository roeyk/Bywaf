"""AST visitor for plugin source capability checking.

Used by:
- `plugin_check` diagnostics, LLM feedback output, CI checks, and external
  plugin author workflows.
- tests that lock down plugin authoring contracts.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from typing import cast

from bywaf.event.schemas import event_schema, validate_event_payload
from .diagnostics import AuthoringDiagnosticMixin
from .helpers import (
    direct_network_call,
    direct_network_module,
    direct_process_call,
    direct_process_module,
    event_payload_argument,
    framework_call_capabilities,
    literal_bool_argument,
    literal_dict_payload,
    literal_string_argument,
    literal_string_sequence,
)
from .state import CapabilityAnalysisState


# Dispatch sequence consumed by CapabilityVisitor.inspect_call(). Each named
# method owns one plugin-check capability surface, keeping call analysis
# extensible without growing a long path/classification ladder.
CALL_INSPECTOR_NAMES = (
    "inspect_authoring_call",
    "inspect_capability_call",
    "inspect_event_store_call",
    "inspect_artifact_call",
    "inspect_filesystem_call",
    "inspect_direct_api_call",
)


class CapabilityVisitor(CapabilityAnalysisState, AuthoringDiagnosticMixin, ast.NodeVisitor):
    """AST visitor for recognizable framework and direct Python API use.

    Constructed by: `bywaf.tools.plugin_check.check_plugin()` for each plugin
    Python source file.

    The visitor has two jobs: infer capabilities from documented framework
    calls, and flag common plugin-authoring mistakes that are hard for generic
    code generators to get right from prose alone.
    """

    def __init__(self, *, path: Path, source: str) -> None:
        self.init_analysis_state(path=path, source=source)
        self.inferred_emits: set[str] = set()
        self.literal_dict_assignments: dict[str, ast.Dict] = {}
        self.has_plugin_factory = False
        self.has_plugins_factory = False
        self.commandlet_decorator_nodes: list[ast.AST] = []

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
        """Track simple literal payload assignments for later publish checks."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Keep only the latest simple `name = {...}` assignment. If the
                # name is reassigned to anything else, later publish validation
                # should no longer treat it as a literal payload.
                if isinstance(node.value, ast.Dict):
                    self.literal_dict_assignments[target.id] = node.value
                else:
                    self.literal_dict_assignments.pop(target.id, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802 - ast API
        """Track annotated literal payload assignments for later publish checks."""
        if isinstance(node.target, ast.Name):
            # Annotated assignments are common in generated plugins:
            # `payload: dict[str, object] = {...}`. Track them like normal
            # assignments for shared-event schema validation.
            if isinstance(node.value, ast.Dict):
                self.literal_dict_assignments[node.target.id] = node.value
            else:
                self.literal_dict_assignments.pop(node.target.id, None)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 - ast API
        """Detect decorators accidentally attached to plugin() factories."""
        if node.name == "plugin":
            self.has_plugin_factory = True
            self.inspect_factory_decorators(node)
        if node.name == "plugins":
            self.has_plugins_factory = True
        self.inspect_commandlet_decorator(node)
        self.visit_function_body(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802 - ast API
        """Detect decorators accidentally attached to async plugin() factories."""
        if node.name == "plugin":
            self.has_plugin_factory = True
            self.inspect_factory_decorators(node)
        if node.name == "plugins":
            self.has_plugins_factory = True
        self.inspect_commandlet_decorator(node)
        self.visit_function_body(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802 - ast API
        """Track commandlet-decorated classes for missing factory diagnostics."""
        self.inspect_commandlet_decorator(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
        """Record import aliases and warn for direct network/process modules."""
        for alias in node.names:
            # Keep a simple alias table so later calls like `requests.get(...)`
            # can be recognized even if the module was imported as `rq`.
            root = alias.name.split(".", 1)[0]
            self.aliases[alias.asname or root] = alias.name if alias.asname else root
            self.record_import_warning(node, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
        """Record from-import aliases and warn for direct network/process APIs."""
        module = node.module or ""
        for alias in node.names:
            qualified = f"{module}.{alias.name}" if module else alias.name
            self.aliases[alias.asname or alias.name] = qualified
            self.record_import_warning(node, qualified)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        """Infer capabilities from framework calls and direct API calls."""
        path = self.call_path(node.func)
        if path:
            self.inspect_call(node, path)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802 - ast API
        """Infer raw database access from context.db attribute reads."""
        path = self.attribute_path(node)
        if path == "context.db":
            self.add_evidence("db.raw", "framework_attribute", node, path)
        self.generic_visit(node)

    def inspect_call(self, node: ast.Call, path: str) -> None:
        """Inspect one call path and record capability evidence.

        Called by: `visit_Call()` after resolving aliases into a dotted call
        path such as `context.events.publish`.
        """
        # CALL_INSPECTOR_NAMES is the dispatch sequence defined above. It
        # replaces a call-path if/elif ladder with small inspectors grouped by
        # capability surface.
        for inspector_name in CALL_INSPECTOR_NAMES:
            inspector = cast(Callable[[ast.Call, str], None], getattr(self, inspector_name))
            inspector(node, path)

    def inspect_capability_call(self, node: ast.Call, path: str) -> None:
        """Infer capabilities from documented framework calls."""
        for framework_capability in framework_call_capabilities(path):
            self.add_evidence(framework_capability, "framework_call", node, path)
        if path == "context.audit_capability":
            capability = literal_string_argument(node, "capability", 0)
            if capability is not None:
                self.add_evidence(capability, "framework_call", node, f"context.audit_capability({capability})")

    def inspect_event_store_call(self, node: ast.Call, path: str) -> None:
        """Infer event store read/write capabilities from context.events calls."""
        if path == "context.events.publish":
            self.inspect_event_publish(node)
        if path in {"context.events.fetch", "context.events.follow"}:
            self.add_event_topics_evidence(node, "db.read")
        if path == "context.events.query":
            topic = literal_string_argument(node, "topic", None)
            self.add_evidence(f"db.read:{topic}" if topic else "db.read:*", "framework_call", node, path)

    def inspect_artifact_call(self, node: ast.Call, path: str) -> None:
        """Infer artifact capabilities from artifact service calls."""
        if path in {"context.artifacts.attach_file", "context.artifacts.attach_files"}:
            self.add_evidence("artifact.write", "framework_call", node, path)
        if path == "context.artifact_store":
            read_access = literal_bool_argument(node, "read_access")
            write_access = literal_bool_argument(node, "write_access")
            if read_access is True:
                self.add_evidence("artifact.read", "framework_call", node, path)
            if write_access is True:
                self.add_evidence("artifact.write", "framework_call", node, path)
            if read_access is not True and write_access is not True:
                self.add_warning(
                    "artifact.read",
                    "artifact_store_access_unspecified",
                    node,
                    "context.artifact_store without read_access=True or write_access=True",
                    confidence="high",
                )

    def inspect_filesystem_call(self, node: ast.Call, path: str) -> None:
        """Warn for direct filesystem API use that should be declared."""
        if path == "open":
            self.inspect_open_call(node)
        if path in {"pathlib.Path.read_text", "pathlib.Path.read_bytes"} or path.endswith(".read_text") or path.endswith(".read_bytes"):
            self.add_warning("filesystem.read", "direct_filesystem", node, path)
        if path in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"} or path.endswith(".write_text") or path.endswith(".write_bytes"):
            self.add_warning("filesystem.write", "direct_filesystem", node, path)

    def inspect_direct_api_call(self, node: ast.Call, path: str) -> None:
        """Warn for direct network/process APIs outside framework helpers."""
        # Direct Python libraries are warnings, not hard errors, because native
        # plugins may intentionally use stdlib APIs while still declaring the
        # right capability.
        if direct_network_call(path):
            self.add_warning("network.connect", "direct_network", node, path, confidence="medium")
        if direct_process_call(path):
            self.add_warning("framework.process.run", "direct_process", node, path, confidence="medium")

    def visit_function_body(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function with common context parameter aliases resolved."""
        previous_aliases: dict[str, str | None] = {}
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if arg.arg in {"context", "ctx", "command_context", "command_ctx"}:
                # Treat common parameter names as the framework CommandContext
                # only within this function body. Restore previous aliases
                # afterward so nested/neighboring functions stay independent.
                previous_aliases[arg.arg] = self.aliases.get(arg.arg)
                self.aliases[arg.arg] = "context"
        try:
            self.generic_visit(node)
        finally:
            for name, previous in previous_aliases.items():
                if previous is None:
                    self.aliases.pop(name, None)
                else:
                    self.aliases[name] = previous

    def inspect_event_publish(self, node: ast.Call) -> None:
        """Add event capability evidence and validate literal shared payloads."""
        topic = literal_string_argument(node, "topic", 0)
        if topic is not None:
            self.inferred_emits.add(topic)
            self.inspect_shared_event_payload(node, topic)
        # If the topic is dynamic, infer a wildcard capability. The checker is
        # advisory; manifest enforcement remains the authoritative gate.
        self.add_evidence(
            f"db.write:{topic}" if topic else "db.write:*",
            "framework_call",
            node,
            self.call_path(node.func) or "",
        )

    def inspect_shared_event_payload(self, node: ast.Call, topic: str) -> None:
        """Validate shared-topic payloads when the payload is a literal dict."""
        if event_schema(topic) is None:
            return
        payload_node = event_payload_argument(node)
        if isinstance(payload_node, ast.Name):
            # Support the common two-step pattern:
            # `payload = {...}; context.events.publish("topic", payload)`.
            payload_node = self.literal_dict_assignments.get(payload_node.id)
        if payload_node is None or not isinstance(payload_node, ast.Dict):
            return
        payload = literal_dict_payload(payload_node)
        if payload is None:
            return
        # Only literal dicts are validated here. Dynamic payloads still require
        # runtime validation by the framework because static AST inference
        # cannot prove their final shape.
        for error in validate_event_payload(topic, payload):
            self.add_diagnostic(
                "error",
                "invalid-shared-event-payload",
                payload_node,
                error,
                "Shared event topics must match bywaf.event.schemas. Add required fields or keep "
                "tool-specific raw detail on a plugin-private topic.",
            )

    def add_event_topics_evidence(self, node: ast.Call, prefix: str) -> None:
        """Add event capability evidence for calls that accept topic sequences."""
        topics = literal_string_sequence(node, "topics", 0)
        if topics:
            # Literal topic lists let plugin_check emit precise db.read:<topic>
            # evidence; dynamic topic lists fall back to wildcard evidence.
            for topic in topics:
                self.add_evidence(f"{prefix}:{topic}", "framework_call", node, self.call_path(node.func) or "")
            return
        self.add_evidence(f"{prefix}:*", "framework_call", node, self.call_path(node.func) or "", confidence="medium")

    def inspect_open_call(self, node: ast.Call) -> None:
        """Infer filesystem read/write from builtin open mode."""
        mode = literal_string_argument(node, "mode", 1) or "r"
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            self.add_warning("filesystem.write", "direct_filesystem", node, f"open(..., mode={mode!r})")
        else:
            self.add_warning("filesystem.read", "direct_filesystem", node, f"open(..., mode={mode!r})")

    def record_import_warning(self, node: ast.AST, qualified: str) -> None:
        """Warn when imports suggest direct network or process execution APIs."""
        if direct_network_module(qualified):
            self.add_warning("network.connect", "direct_network_import", node, f"import {qualified}", confidence="medium")
        if direct_process_module(qualified):
            self.add_warning("framework.process.run", "direct_process_import", node, f"import {qualified}", confidence="medium")
