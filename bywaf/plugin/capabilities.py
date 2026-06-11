"""Capability helpers for plugin-facing framework APIs.

Provides the audit-only capability matching and implied-capability derivation
used when commandlets interact with framework-owned services.

Used by:
- `plugin_context`: audits commandlet capability usage.
- `runner.context`: derives capabilities from commandlet metadata."""

from __future__ import annotations

from collections.abc import Iterable
from zlib import crc32

from ..specs import CommandSpec

DATABASE_ACTIONS = ("view", "write", "manage")

# Capability codes are audit labels, not authorization rules.
# capability_code_label() uses this lookup table to keep stable human-readable
# C### labels for framework-defined capabilities, while topic-scoped DB
# capabilities get generated subcodes.
ASSIGNED_CAPABILITY_CODES = {
    "db.raw": "C201",
    "artifact.read": "C202",
    "artifact.write": "C203",
    "framework.process.run": "C301",
    "framework.process.stream": "C302",
    "filesystem.read": "C311",
    "filesystem.write": "C312",
    "network.connect": "C401",
    "network.listen": "C402",
    "framework.secret.prompt": "C501",
    "framework.secret.resolve": "C502",
    "framework.job.control": "C601",
    "finding.review": "C602",
    "framework.console.output": "C701",
    "framework.console.alert": "C702",
    "framework.file.page": "C703",
    "framework.render.table": "C704",
    "plugin.progress": "C801",
}


def framework_request_capability(topic: str) -> str | None:
    """Map a framework request topic to the capability it uses."""
    exact = request_capability_map().get(topic)
    if exact is not None:
        return exact
    # Prefix mappings let plugin progress/job-control families grow without
    # adding a one-off entry for every event topic.
    for prefix, capability in request_prefix_caps().items():
        if topic.startswith(prefix):
            return capability
    if topic.startswith("framework.") and topic.endswith(".requested"):
        return "framework.request"
    return None


def request_capability_map() -> dict[str, str]:
    """Return exact framework request topic capability mappings."""
    return {
        "framework.console.output.requested": "framework.console.output",
        "framework.console.alert.requested": "framework.console.alert",
        "framework.file.page.requested": "framework.file.page",
        "framework.process.run.requested": "framework.process.run",
        "framework.process.stream.requested": "framework.process.stream",
        "framework.render.table.requested": "framework.render.table",
        "shell.prompt.requested": "framework.prompt.change",
    }


def request_prefix_caps() -> dict[str, str]:
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


def capability_code_label(capability: str) -> str:
    """Return the assigned C### code, topic family code, or accepted range."""
    exact = ASSIGNED_CAPABILITY_CODES.get(capability)
    if exact is not None:
        return exact
    if capability.startswith("db.read:"):
        return topic_capability_code("C101", capability.removeprefix("db.read:"))
    if capability.startswith("db.write:"):
        return topic_capability_code("C102", capability.removeprefix("db.write:"))
    return capability_family_range(capability)


def topic_capability_code(family_code: str, topic: str) -> str:
    """Return a stable dotted subcode for a topic-specific capability."""
    subcode = crc32(topic.encode("utf-8")) % 1_000_000
    return f"{family_code}.{subcode:06d}"


def capability_family_range(capability: str) -> str:
    """Return the accepted capability-code family range for a capability."""
    if capability.startswith("db.read:") or capability.startswith("db.write:"):
        return "C100-C199"
    if capability.startswith("db.") or capability.startswith("artifact."):
        return "C200-C299"
    if capability.startswith("process.") or capability.startswith("filesystem."):
        return "C300-C399"
    if capability.startswith("network."):
        return "C400-C499"
    if capability.startswith("framework.secret"):
        return "C500-C599"
    if capability.startswith("framework.job") or capability.startswith("framework.pipeline"):
        return "C600-C699"
    if capability.startswith("framework.render"):
        return "C700-C799"
    if capability.startswith("plugin."):
        return "C800-C899"
    if capability.startswith("framework."):
        return "C001-C099"
    return "C900-C999"


def db_actions_for_caps(capabilities: Iterable[str]) -> tuple[str, ...]:
    """Infer coarse database actions from DB-related capability declarations."""
    actions: set[str] = set()
    for capability in capabilities:
        if capability.startswith("db.manage") or capability.startswith("db.raw"):
            actions.add("manage")
        elif capability.startswith("db.write:"):
            actions.add("write")
        elif capability.startswith("db.read:"):
            actions.add("view")
    return tuple(action for action in DATABASE_ACTIONS if action in actions)


def database_action_for_capability(capability: str) -> str | None:
    """Return the coarse database action needed by one capability."""
    if capability.startswith("db.manage") or capability.startswith("db.raw"):
        return "manage"
    if capability.startswith("db.write:"):
        return "write"
    if capability.startswith("db.read:"):
        return "view"
    return None


def database_action_allowed(required: str, allowed: Iterable[str]) -> bool:
    """Return whether a declared action set allows the required DB operation."""
    declared = set(allowed)
    if required == "view":
        return bool(declared & {"view", "write", "manage"})
    if required == "write":
        return bool(declared & {"write", "manage"})
    if required == "manage":
        return "manage" in declared
    return False


def implied_capabilities(spec: CommandSpec) -> tuple[str, ...]:
    """Return capabilities implied by commandlet metadata."""
    capabilities = set(spec.capabilities)
    # consumes/emits are event schemas, so derive the corresponding DB
    # read/write permissions for checker and audit consistency.
    capabilities.update(f"db.read:{topic}" for topic in spec.consumes)
    capabilities.update(f"db.write:{topic}" for topic in spec.emits)
    return tuple(sorted(capabilities))
