"""AST visitor for plugin source capability checking."""

from __future__ import annotations

import ast
from pathlib import Path

from bywaf.event.schemas import event_schema, validate_event_payload
from bywaf.tools.plugin_check_helpers import (
    boolean_like_option_name,
    call_basename,
    direct_network_call,
    direct_network_module,
    direct_process_call,
    direct_process_module,
    event_payload_argument,
    framework_call_capabilities,
    literal_bool_argument,
    literal_dict_payload,
    literal_string_argument,
    literal_string_sequence_argument,
)
from bywaf.tools.plugin_check_model import CapabilityEvidence, SourceDiagnostic


class CapabilityVisitor(ast.NodeVisitor):
    """AST visitor for recognizable framework and direct Python API use.

    The visitor has two jobs: infer capabilities from documented framework
    calls, and flag common plugin-authoring mistakes that are hard for generic
    code generators to get right from prose alone.
    """

    def __init__(self, *, path: Path, source: str) -> None:
        self.path = path
        self.source = source
        self.aliases: dict[str, str] = {}
        self.evidence: list[CapabilityEvidence] = []
        self.warnings: list[CapabilityEvidence] = []
        self.diagnostics: list[SourceDiagnostic] = []
        self.inferred_emits: set[str] = set()
        self.literal_dict_assignments: dict[str, ast.Dict] = {}

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
        """Track simple literal payload assignments for later publish checks."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Dict):
                    self.literal_dict_assignments[target.id] = node.value
                else:
                    self.literal_dict_assignments.pop(target.id, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802 - ast API
        """Track annotated literal payload assignments for later publish checks."""
        if isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Dict):
                self.literal_dict_assignments[node.target.id] = node.value
            else:
                self.literal_dict_assignments.pop(node.target.id, None)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 - ast API
        """Detect decorators accidentally attached to plugin() factories."""
        if node.name == "plugin":
            self.inspect_plugin_factory_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802 - ast API
        """Detect decorators accidentally attached to async plugin() factories."""
        if node.name == "plugin":
            self.inspect_plugin_factory_decorators(node)
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
        """Inspect one call path and record capability evidence."""
        self.inspect_authoring_call(node, path)
        for framework_capability in framework_call_capabilities(path):
            self.add_evidence(framework_capability, "framework_call", node, path)

        # Calls through CommandContext are high-confidence evidence because they
        # map directly to Bywaf capabilities. Direct Python libraries are
        # warnings, not hard errors, because native plugins may intentionally
        # use stdlib APIs while still declaring the right capability.
        if path == "context.audit_capability":
            capability = literal_string_argument(node, "capability", 0)
            if capability is not None:
                self.add_evidence(capability, "framework_call", node, f"context.audit_capability({capability})")
        if path == "context.events.publish":
            self.inspect_event_publish(node)
        if path in {"context.events.fetch", "context.events.follow"}:
            self.add_event_topics_evidence(node, "db.read")
        if path == "context.events.query":
            topic = literal_string_argument(node, "topic", None)
            self.add_evidence(f"db.read:{topic}" if topic else "db.read:*", "framework_call", node, path)
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
        if path == "open":
            self.inspect_open_call(node)
        if path in {"pathlib.Path.read_text", "pathlib.Path.read_bytes"} or path.endswith(".read_text") or path.endswith(".read_bytes"):
            self.add_warning("filesystem.read", "direct_filesystem", node, path)
        if path in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"} or path.endswith(".write_text") or path.endswith(".write_bytes"):
            self.add_warning("filesystem.write", "direct_filesystem", node, path)
        if direct_network_call(path):
            self.add_warning("network.connect", "direct_network", node, path, confidence="medium")
        if direct_process_call(path):
            self.add_warning("framework.process.run", "direct_process", node, path, confidence="medium")

    def inspect_plugin_factory_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Report commandlet metadata decorators on plugin() instead of the commandlet class."""
        for decorator in node.decorator_list:
            path = self.call_path(decorator.func) if isinstance(decorator, ast.Call) else self.call_path(decorator)
            if call_basename(path) in {"argument", "commandlet", "option"}:
                self.add_diagnostic(
                    "error",
                    "decorator-on-plugin-factory",
                    decorator,
                    f"@{call_basename(path)} decorates plugin()",
                    "@commandlet can decorate a manifest-backed function or a CommandletBase class, but not "
                    "plugin(). Keep plugin() as an undecorated factory that only returns the commandlet object.",
                )

    def inspect_authoring_call(self, node: ast.Call, path: str) -> None:
        """Report common plugin-authoring mistakes before import/runtime failures.

        These diagnostics are intentionally opinionated guardrails. They catch
        mistakes repeatedly made by LLM-generated plugins, such as putting
        argparse keywords in metadata decorators or inventing helper APIs.
        """
        basename = call_basename(path)
        if basename == "argument":
            self.inspect_allowed_keywords(
                node,
                allowed={"required", "completion"},
                code="invalid-argument-decorator-keyword",
                guidance=(
                    "@argument records positional metadata only. Put argparse behavior such as nargs, default, "
                    "choices, or action in parser.add_argument(...) inside run()/parse_args()."
                ),
            )
        if basename == "option":
            self.inspect_allowed_keywords(
                node,
                allowed={"default", "choices", "completion", "secret"},
                code="invalid-option-decorator-keyword",
                guidance=(
                    "@option records option metadata only. Supported keywords are default, choices, completion, "
                    "and secret. Put argparse behavior such as action='store_true' in parser.add_argument(...)."
                ),
            )
            self.inspect_boolean_like_option(node)
        if path in {"context.is_cancelled"}:
            self.add_diagnostic(
                "error",
                "unsupported-context-is-cancelled",
                node,
                "context.is_cancelled() is not the documented cancellation API",
                "Use context.raise_if_cancelled() inside long-running loops.",
            )
        if basename in {"candidate_payload", "confirmed_payload"}:
            self.inspect_allowed_keywords(
                node,
                allowed={
                    "title",
                    "finding_class",
                    "target",
                    "severity",
                    "confidence",
                    "evidence",
                    "affected",
                    "finding_scope",
                    "target_scope",
                    "group_key",
                    "recommendation",
                    "identifiers",
                    "source",
                    "subjects",
                },
                code=f"invalid-{basename.replace('_', '-')}-keyword",
                guidance=f"Use the exact bywaf.finding.{basename}(...) keyword names from the docs.",
            )

    def inspect_allowed_keywords(self, node: ast.Call, *, allowed: set[str], code: str, guidance: str) -> None:
        """Report unsupported keyword arguments for known public helper APIs."""
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg not in allowed:
                self.add_diagnostic(
                    "error",
                    code,
                    keyword.value,
                    f"unsupported keyword {keyword.arg!r}",
                    guidance,
                )

    def inspect_boolean_like_option(self, node: ast.Call) -> None:
        """Report boolean-looking option metadata that omits explicit defaults."""
        option_name = literal_string_argument(node, "name", 0)
        if option_name is None or not boolean_like_option_name(option_name):
            return
        has_default = len(node.args) > 2 or any(keyword.arg == "default" for keyword in node.keywords)
        if has_default:
            return
        # Boolean options are ambiguous in metadata unless the default and
        # choices are explicit. Runtime argparse may still use store_true, but
        # the manifest/checker/completion layer needs declarative values.
        self.add_diagnostic(
            "error",
            "boolean-option-missing-default",
            node,
            f"boolean-like option {option_name!r} has no documented default",
            "For boolean-style options, declare metadata with an explicit string default and choices, for example "
            "@option('confirm', 'perform confirmation', 'false', ('true', 'false')), then parse the runtime flag "
            "inside run()/parse_args().",
        )

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
            payload_node = self.literal_dict_assignments.get(payload_node.id)
        if payload_node is None or not isinstance(payload_node, ast.Dict):
            return
        payload = literal_dict_payload(payload_node)
        if payload is None:
            return
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
        topics = literal_string_sequence_argument(node, "topics", 0)
        if topics:
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

    def add_evidence(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str = "high",
    ) -> None:
        """Append one inferred capability evidence record."""
        self.evidence.append(self.make_record(capability, kind, node, detail, confidence=confidence))

    def add_warning(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str = "high",
    ) -> None:
        """Append one advisory warning record."""
        self.warnings.append(self.make_record(capability, kind, node, detail, confidence=confidence))

    def add_diagnostic(
        self,
        severity: str,
        code: str,
        node: ast.AST,
        message: str,
        guidance: str,
    ) -> None:
        """Append one plugin-authoring diagnostic."""
        self.diagnostics.append(
            SourceDiagnostic(
                severity=severity,
                code=code,
                path=str(self.path),
                line=getattr(node, "lineno", 0),
                message=message,
                guidance=guidance,
            )
        )

    def make_record(
        self,
        capability: str,
        kind: str,
        node: ast.AST,
        detail: str,
        *,
        confidence: str,
    ) -> CapabilityEvidence:
        """Build an evidence record with source location."""
        segment = ast.get_source_segment(self.source, node)
        if segment:
            detail = segment.strip().splitlines()[0]
        return CapabilityEvidence(
            capability=capability,
            kind=kind,
            path=str(self.path),
            line=getattr(node, "lineno", 0),
            detail=detail,
            confidence=confidence,
        )

    def call_path(self, node: ast.AST) -> str:
        """Return a dotted call path, with simple import aliases resolved."""
        path = self.attribute_path(node)
        if not path:
            return ""
        parts = path.split(".")
        if parts[0] in self.aliases:
            resolved = self.aliases[parts[0]]
            return ".".join((resolved, *parts[1:]))
        return path

    def attribute_path(self, node: ast.AST) -> str:
        """Return a dotted attribute/name path for a simple expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self.attribute_path(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self.attribute_path(node.func)
        return ""
