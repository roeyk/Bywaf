"""Source analysis helpers for plugin checking.

Provides lightweight AST inference for capabilities and risky direct API use in
filesystem plugins.

Used by:
- scripts/plugin_check.py: report inferred capabilities and evidence.
- tests: exercise plugin author tooling without running plugin code."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    """One source-code observation that implies or warns about a capability."""

    capability: str
    kind: str
    path: str
    line: int
    detail: str
    confidence: str = "high"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable evidence record."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SourceAnalysis:
    """Capability inference result for one plugin source tree."""

    inferred_capabilities: tuple[str, ...]
    evidence: tuple[CapabilityEvidence, ...]
    warnings: tuple[CapabilityEvidence, ...]
    diagnostics: tuple["SourceDiagnostic", ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable analysis result."""
        return {
            "inferred_capabilities": list(self.inferred_capabilities),
            "evidence": [item.to_dict() for item in self.evidence],
            "warnings": [item.to_dict() for item in self.warnings],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class SourceDiagnostic:
    """One plugin-authoring diagnostic suitable for LLM feedback."""

    severity: str
    code: str
    path: str
    line: int
    message: str
    guidance: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable diagnostic record."""
        return asdict(self)


def analyze_plugin_source(plugin_dir: Path) -> SourceAnalysis:
    """Infer likely capabilities from Python source without importing it."""
    evidence: list[CapabilityEvidence] = []
    warnings: list[CapabilityEvidence] = []
    diagnostics: list[SourceDiagnostic] = []
    for path in sorted(plugin_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        visitor = CapabilityVisitor(path=path, source=source)
        visitor.visit(tree)
        evidence.extend(visitor.evidence)
        warnings.extend(visitor.warnings)
        diagnostics.extend(visitor.diagnostics)
    capabilities = sorted({item.capability for item in evidence})
    return SourceAnalysis(tuple(capabilities), tuple(evidence), tuple(warnings), tuple(diagnostics))


class CapabilityVisitor(ast.NodeVisitor):
    """AST visitor for recognizable framework and direct Python API use."""

    def __init__(self, *, path: Path, source: str) -> None:
        self.path = path
        self.source = source
        self.aliases: dict[str, str] = {}
        self.evidence: list[CapabilityEvidence] = []
        self.warnings: list[CapabilityEvidence] = []
        self.diagnostics: list[SourceDiagnostic] = []

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
        framework_capability = framework_call_capability(path)
        if framework_capability is not None:
            self.add_evidence(framework_capability, "framework_call", node, path)
        if path == "context.audit_capability":
            capability = literal_string_argument(node, "capability", 0)
            if capability is not None:
                self.add_evidence(capability, "framework_call", node, f"context.audit_capability({capability})")
        if path == "context.events.publish":
            self.add_event_topic_evidence(node, "db.write")
        if path in {"context.events.fetch", "context.events.follow"}:
            self.add_event_topics_evidence(node, "db.read")
        if path == "context.events.query":
            topic = literal_string_argument(node, "topic", None)
            self.add_evidence(f"db.read:{topic}" if topic else "db.read:*", "framework_call", node, path)
        if path in {"context.artifacts.attach_file", "context.artifacts.attach_files"}:
            self.add_evidence("artifact.write", "framework_call", node, path)
        if path == "open":
            self.inspect_open_call(node)
        if path in {"pathlib.Path.read_text", "pathlib.Path.read_bytes"} or path.endswith(".read_text") or path.endswith(".read_bytes"):
            self.add_warning("filesystem.read", "direct_filesystem", node, path)
        if path in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"} or path.endswith(".write_text") or path.endswith(".write_bytes"):
            self.add_warning("filesystem.write", "direct_filesystem", node, path)
        if direct_network_call(path):
            self.add_warning("network.connect", "direct_network", node, path, confidence="medium")
        if direct_process_call(path):
            self.add_warning("process.run", "direct_process", node, path, confidence="medium")

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
                    "@commandlet, @argument, and @option must decorate the CommandletBase class in plugin.py. "
                    "Keep plugin() as an undecorated factory that only returns the commandlet instance.",
                )

    def inspect_authoring_call(self, node: ast.Call, path: str) -> None:
        """Report common plugin-authoring mistakes before import/runtime failures."""
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
        if basename == "confirmed_payload":
            self.add_diagnostic(
                "error",
                "no-confirmed-payload-helper",
                node,
                "bywaf.findings.confirmed_payload(...) does not exist",
                "Use bywaf.findings.candidate_payload(...) and then set payload['status'] = 'confirmed'.",
            )
        if basename == "candidate_payload":
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
                    "group_key",
                    "recommendation",
                    "identifiers",
                    "source",
                },
                code="invalid-candidate-payload-keyword",
                guidance="Use the exact bywaf.findings.candidate_payload(...) keyword names from the docs.",
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
        self.add_diagnostic(
            "error",
            "boolean-option-missing-default",
            node,
            f"boolean-like option {option_name!r} has no documented default",
            "For boolean-style options, declare metadata with an explicit string default and choices, for example "
            "@option('confirm', 'perform confirmation', 'false', ('true', 'false')), then parse the runtime flag "
            "inside run()/parse_args().",
        )

    def add_event_topic_evidence(self, node: ast.Call, prefix: str) -> None:
        """Add exact or wildcard event capability evidence for publish calls."""
        topic = literal_string_argument(node, "topic", 0)
        self.add_evidence(f"{prefix}:{topic}" if topic else f"{prefix}:*", "framework_call", node, self.call_path(node.func) or "")

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
            self.add_warning("process.run", "direct_process_import", node, f"import {qualified}", confidence="medium")

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


def framework_call_capability(path: str) -> str | None:
    """Return the capability implied by a known framework API call."""
    return {
        "context.alert": "framework.console.alert",
        "context.output": "framework.console.output",
        "context.page_file": "framework.file.page",
        "context.page_text": "framework.file.page",
        "context.table": "framework.render.table",
        "context.render.table": "framework.render.table",
        "context.process.run": "process.run",
        "context.process.stream": "process.run",
        "context.require_db": "db.raw",
        "context.maintenance_store": "db.raw",
        "context.progress": "plugin.progress",
        "context.progress_started": "plugin.progress",
        "context.progress_completed": "plugin.progress",
        "context.progress_failed": "plugin.progress",
        "context.secrets.resolve": "framework.secret.resolve",
        "context.artifacts.attach_file": "filesystem.read",
        "context.artifacts.attach_files": "filesystem.read",
    }.get(path)


def literal_string_argument(node: ast.Call, keyword: str, position: int | None) -> str | None:
    """Return a literal string argument by keyword or position."""
    for item in node.keywords:
        if item.arg == keyword and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
            return item.value.value
    if position is not None and len(node.args) > position:
        value = node.args[position]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def literal_string_sequence_argument(node: ast.Call, keyword: str, position: int) -> tuple[str, ...]:
    """Return literal strings from a tuple/list argument."""
    for item in node.keywords:
        if item.arg == keyword:
            return literal_string_sequence(item.value)
    if len(node.args) > position:
        return literal_string_sequence(node.args[position])
    return ()


def literal_string_sequence(node: ast.AST) -> tuple[str, ...]:
    """Return strings from a literal list or tuple."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, (ast.Tuple, ast.List)):
        values: list[str] = []
        for item in node.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return ()
            values.append(item.value)
        return tuple(values)
    return ()


def call_basename(path: str) -> str:
    """Return the final component of a dotted call path."""
    return path.rsplit(".", 1)[-1] if path else ""


def boolean_like_option_name(name: str) -> bool:
    """Return whether an option name is usually modeled as a boolean toggle."""
    normalized = name.replace("_", "-").lower()
    if normalized in {"confirm", "force", "quiet", "silent", "ssl", "verbose"}:
        return True
    return normalized.startswith(("enable-", "disable-", "no-", "use-"))


def direct_network_module(path: str) -> bool:
    """Return whether an import path is a direct network-capable module."""
    if path == "urllib.parse" or path.startswith("urllib.parse."):
        return False
    return path.split(".", 1)[0] in {
        "ftplib",
        "http",
        "imaplib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "telnetlib",
        "urllib",
    }


def direct_process_module(path: str) -> bool:
    """Return whether an import path is a direct process-execution module."""
    return path.split(".", 1)[0] in {"pty", "subprocess"}


def direct_network_call(path: str) -> bool:
    """Return whether a call path suggests direct network access."""
    return direct_network_module(path) and path not in {"urllib.parse"}


def direct_process_call(path: str) -> bool:
    """Return whether a call path suggests direct process execution."""
    if path in {"os.system", "os.popen", "pty.spawn"}:
        return True
    return path.startswith("subprocess.")
