"""Authoring diagnostics for plugin source checking."""

from __future__ import annotations

import ast
from typing import Protocol, cast

from bywaf.tools.plugin_check_helpers import (
    boolean_like_option_name,
    call_basename,
    literal_string_argument,
)


class _DiagnosticState(Protocol):
    """Protocol implemented by the concrete checker visitor."""

    commandlet_decorator_nodes: list[ast.AST]

    def call_path(self, node: ast.AST) -> str: ...

    def add_diagnostic(
        self,
        severity: str,
        code: str,
        node: ast.AST,
        message: str,
        guidance: str,
    ) -> None: ...


class AuthoringDiagnosticMixin:
    """Diagnostics for common plugin-authoring mistakes."""

    def inspect_plugin_factory_decorators(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Report commandlet metadata decorators on plugin() instead of the commandlet class."""
        state = cast(_DiagnosticState, self)
        for decorator in node.decorator_list:
            path = state.call_path(decorator.func) if isinstance(decorator, ast.Call) else state.call_path(decorator)
            if call_basename(path) in {"argument", "commandlet", "option"}:
                state.add_diagnostic(
                    "error",
                    "decorator-on-plugin-factory",
                    decorator,
                    f"@{call_basename(path)} decorates plugin()",
                    "@commandlet can decorate a manifest-backed function or a CommandletBase class, but not "
                    "plugin(). Keep plugin() as an undecorated factory that only returns the commandlet object.",
                )

    def inspect_commandlet_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        """Track functions/classes decorated as commandlets."""
        state = cast(_DiagnosticState, self)
        for decorator in node.decorator_list:
            path = state.call_path(decorator.func) if isinstance(decorator, ast.Call) else state.call_path(decorator)
            if call_basename(path) == "commandlet":
                state.commandlet_decorator_nodes.append(decorator)

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
            state = cast(_DiagnosticState, self)
            state.add_diagnostic(
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
        state = cast(_DiagnosticState, self)
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg not in allowed:
                state.add_diagnostic(
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
        state = cast(_DiagnosticState, self)
        state.add_diagnostic(
            "error",
            "boolean-option-missing-default",
            node,
            f"boolean-like option {option_name!r} has no documented default",
            "For boolean-style options, declare metadata with an explicit string default and choices, for example "
            "@option('confirm', 'perform confirmation', 'false', ('true', 'false')), then parse the runtime flag "
            "inside run()/parse_args().",
        )
