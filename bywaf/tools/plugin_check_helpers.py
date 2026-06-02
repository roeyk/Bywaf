"""Standalone AST helper functions for plugin source checking."""

from __future__ import annotations

import ast
from typing import Any

def framework_call_capabilities(path: str) -> tuple[str, ...]:
    """Return capabilities implied by a known framework API call."""
    return {
        "context.alert": ("framework.console.alert",),
        "context.output": ("framework.console.output",),
        "context.page_file": ("framework.file.page",),
        "context.page_text": ("framework.file.page",),
        "context.table": ("framework.render.table",),
        "context.render.table": ("framework.render.table",),
        "context.process.run": ("framework.process.run", "artifact.write"),
        "context.process.stream": ("framework.process.stream",),
        "context.require_db": ("db.raw",),
        "context.maintenance_store": ("db.raw",),
        "context.progress": ("plugin.progress",),
        "context.progress_started": ("plugin.progress",),
        "context.progress_completed": ("plugin.progress",),
        "context.progress_failed": ("plugin.progress",),
        "context.secrets.resolve": ("framework.secret.resolve",),
        "context.artifacts.attach_file": ("filesystem.read",),
        "context.artifacts.attach_files": ("filesystem.read",),
    }.get(path, ())


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


def literal_bool_argument(node: ast.Call, keyword: str) -> bool | None:
    """Return a literal boolean keyword argument."""
    for item in node.keywords:
        if item.arg == keyword and isinstance(item.value, ast.Constant) and isinstance(item.value.value, bool):
            return item.value.value
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


def event_payload_argument(node: ast.Call) -> ast.AST | None:
    """Return the payload argument from context.events.publish(...)."""
    for item in node.keywords:
        if item.arg == "payload":
            return item.value
    if len(node.args) > 1:
        return node.args[1]
    return None


def literal_dict_payload(node: ast.Dict) -> dict[str, Any] | None:
    """Return a shallow literal dict payload, or None when dynamic."""
    payload: dict[str, Any] = {}
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            return None
        try:
            payload[key_node.value] = ast.literal_eval(value_node)
        except (ValueError, TypeError):
            return None
    return payload


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
