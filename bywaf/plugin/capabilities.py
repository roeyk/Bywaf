"""Capability helpers for plugin-facing framework APIs.

Provides the audit-only capability matching and implied-capability derivation
used when commandlets interact with framework-owned services.

Used by:
- `plugin_context`: audits commandlet capability usage.
- `runner.context`: derives capabilities from commandlet metadata."""

from __future__ import annotations

from collections.abc import Iterable

from ..specs import CommandSpec


def framework_request_capability(topic: str) -> str | None:
    """Map a framework request topic to the capability it uses."""
    exact = framework_request_capability_map().get(topic)
    if exact is not None:
        return exact
    # Prefix mappings let plugin progress/job-control families grow without
    # adding a one-off entry for every event topic.
    for prefix, capability in framework_request_prefix_capabilities().items():
        if topic.startswith(prefix):
            return capability
    if topic.startswith("framework.") and topic.endswith(".requested"):
        return "framework.request"
    return None


def framework_request_capability_map() -> dict[str, str]:
    """Return exact framework request topic capability mappings."""
    return {
        "framework.console.output.requested": "framework.console.output",
        "framework.console.alert.requested": "framework.console.alert",
        "framework.file.page.requested": "framework.file.page",
        "framework.process.run.requested": "process.run",
        "framework.process.stream.requested": "process.run",
        "framework.render.table.requested": "framework.render.table",
        "shell.prompt.requested": "framework.prompt.change",
    }


def framework_request_prefix_capabilities() -> dict[str, str]:
    """Return prefix-based framework request capability mappings."""
    return {
        "plugin.progress.": "plugin.progress",
        "framework.job.": "framework.job.control",
        "framework.pipeline.": "framework.pipeline.control",
    }


def capability_declared(capability: str, declarations: Iterable[str]) -> bool:
    """Return whether a capability is exactly declared or covered by a wildcard."""
    for declaration in declarations:
        if capability == declaration:
            return True
        if declaration.endswith(":*") and capability.startswith(declaration[:-1]):
            # Wildcards are prefix wildcards for capability families such as
            # db.read:*; they are not general glob patterns.
            return True
    return False


def implied_capabilities(spec: CommandSpec) -> tuple[str, ...]:
    """Return capabilities implied by commandlet metadata."""
    capabilities = set(spec.capabilities)
    # consumes/emits are event contracts, so derive the corresponding DB
    # read/write permissions for checker and audit consistency.
    capabilities.update(f"db.read:{topic}" for topic in spec.consumes)
    capabilities.update(f"db.write:{topic}" for topic in spec.emits)
    return tuple(sorted(capabilities))
