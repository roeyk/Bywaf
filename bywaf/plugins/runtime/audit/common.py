"""Shared audit command constants.

Centralizes action names, export formats, and accepted selector keys for the
audit commandlet and its helper modules.

Used by:
- runtime.audit: declare command metadata.
- runtime.audit.selectors and runtime.audit.export: validate selectors."""

from __future__ import annotations

from collections.abc import Callable
from argparse import Namespace

from bywaf.plugin import CommandContext

AUDIT_ACTIONS = ("export", "list", "show")
AUDIT_LIST_TARGETS = ("capabilities", "policy", "topics")
AUDIT_FORMATS = ("json", "jsonl", "pdf", "sqlite")
AUDIT_SELECTORS = {"file", "topic", "step", "pipeline", "job", "serial", "since", "until"}
AUDIT_LIST_SELECTORS = {"decision", "job", "pipeline", "plugin", "reason", "serial", "since", "step", "target", "topic", "until"}

AuditActionHandler = Callable[[CommandContext, Namespace, dict[str, str]], None]
