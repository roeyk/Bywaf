"""Artifact selector parsing and runtime-scope resolution.

Translates user-facing selectors such as `job=1`, `pipeline=2`, `step=3`, and
durable `serial=` values into the provenance columns stored on artifacts.

Used by:
- runtime.artifact.actions: resolve mutation/list/export scopes.
- runtime.artifact.query: select and search artifacts by provenance."""

from __future__ import annotations

from dataclasses import dataclass

from bywaf.plugin import CommandContext

from .common import SEARCH_FLAGS


def parse_artifact_selectors(tokens: list[str], *, allow_page: bool = False) -> dict[str, list[str]]:
    """Parse artifact key=value selectors, preserving repeated file= values.

    Called by: artifact list/show/export/remove/replace/verify handlers.
    """
    selectors: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--page" and allow_page:
            selectors.setdefault("page", []).append("true")
            index += 1
            continue
        if "=" not in token:
            raise ValueError(f"invalid artifact selector: {token}")
        key, value = token.split("=", 1)
        if key == "note":
            # note= intentionally consumes the rest of the line so operators can
            # write natural-language notes without quoting every word.
            value = " ".join([value, *tokens[index + 1:]]).strip()
            index = len(tokens)
        else:
            index += 1
        if key not in {"artifact", "step", "pipeline", "job", "serial", "topic", "file", "dir", "name", "note"}:
            raise ValueError(f"unknown artifact selector: {key}")
        if not value:
            raise ValueError(f"artifact selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
    return selectors


def parse_artifact_cat_selectors(tokens: list[str]) -> dict[str, list[str]]:
    """Parse selectors for artifact body preview.

    Called by: artifact cat handler.
    """
    selectors: dict[str, list[str]] = {}
    for token in tokens:
        if token == "--page":
            selectors.setdefault("page", []).append("true")
            continue
        if "=" not in token:
            raise ValueError(f"invalid artifact cat selector: {token}")
        key, value = token.split("=", 1)
        if key not in {"artifact", "step", "pipeline", "job", "serial", "topic", "limit", "encoding"}:
            raise ValueError(f"unknown artifact cat selector: {key}")
        if not value:
            raise ValueError(f"artifact cat selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
    return selectors


def parse_search_selectors(tokens: list[str]) -> dict[str, list[str]]:
    """Parse search selectors and scope flags.

    Called by: artifact search commandlet.
    """
    selectors: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SEARCH_FLAGS:
            # Flags are stored in the same selector map as key=value filters so
            # downstream query code has one structure to inspect.
            selectors.setdefault(token.removeprefix("--"), []).append("true")
            index += 1
            continue
        if "=" not in token:
            raise ValueError(f"invalid search selector: {token}")
        key, value = token.split("=", 1)
        if key not in {"artifact", "step", "pipeline", "job", "serial", "name", "filename", "note", "content", "since", "until"}:
            raise ValueError(f"unknown search selector: {key}")
        if not value:
            raise ValueError(f"search selector {key}= requires a value")
        selectors.setdefault(key, []).append(value)
        index += 1
    return selectors


def pop_page_flag(selectors: dict[str, list[str]]) -> bool:
    """Remove and return the internal artifact-list page flag.

    Called by: artifact list/display handlers after parsing selectors.
    """
    return bool(selectors.pop("page", []))


@dataclass(frozen=True, slots=True)
class ArtifactScope:
    """Resolved artifact provenance selectors.

    Constructed by: artifact selector resolution helpers.
    Used by: artifact query functions when reading provenance columns.
    """

    job_id: str | None = None
    pipeline_id: str | None = None
    command_run_id: str | None = None


def resolve_artifact_scope(context: CommandContext, selectors: dict[str, list[str]]) -> ArtifactScope:
    """Resolve step/pipeline/job/serial selectors into artifact provenance scope.

    Called by: artifact query/search paths after selector parsing.
    """
    serial = single_value(selectors, "serial")
    explicit = ArtifactScope(
        job_id=resolve_job_selector(context, single_value(selectors, "job")),
        pipeline_id=resolve_pipeline_selector(context, single_value(selectors, "pipeline")),
        command_run_id=resolve_run_selector(context, single_value(selectors, "step")),
    )
    if serial is None:
        return explicit
    if any((explicit.job_id, explicit.pipeline_id, explicit.command_run_id)):
        raise ValueError("serial= cannot be combined with step=, pipeline=, or job=")
    # serial= is the durable selector form. It resolves to the same underlying
    # provenance columns as the shorter local IDs.
    return resolve_serial_scope(context, serial)


def resolve_serial_scope(context: CommandContext, serial: str) -> ArtifactScope:
    """Resolve a durable runtime serial to an artifact provenance scope.

    Called by: `resolve_artifact_scope()` for `serial=`.
    """
    if serial.startswith("artifact-"):
        # artifact- serials identify an artifact row, not the runtime entity
        # that produced it; use artifact= for direct artifact selection.
        raise ValueError("artifacts are not attached to other artifacts; use artifact= to select existing artifacts")
    if serial.startswith("pipeline-"):
        return ArtifactScope(pipeline_id=serial)
    if serial.startswith("job-"):
        job_id = resolve_job_serial(context, serial)
        if job_id is None:
            raise ValueError(f"unknown job serial: {serial}")
        return ArtifactScope(job_id=job_id)
    return ArtifactScope(command_run_id=serial)


def resolve_job_serial(context: CommandContext, serial: str) -> str | None:
    """Resolve a durable job serial to the local job id stored with artifacts.

    Called by: artifact serial/job selector helpers.
    """
    return context.runtime_store("artifact").job_id_for_serial(serial)


def resolve_job_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a local job id or durable job serial for artifact selectors.

    Called by: `resolve_artifact_scope()`.
    """
    if value is None:
        return None
    if value.isdigit():
        return value
    resolved = context.runtime_store("artifact").job_id_for_serial(value)
    if resolved is None:
        raise ValueError(f"unknown job: {value}")
    return resolved


def resolve_run_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing step id to the durable step serial.

    Called by: `resolve_artifact_scope()`.
    """
    if value is None:
        return None
    return context.runtime_store("artifact").resolve_run_serial(value)


def resolve_pipeline_selector(context: CommandContext, value: str | None) -> str | None:
    """Resolve a user-facing pipeline id to the durable pipeline serial.

    Called by: `resolve_artifact_scope()`.
    """
    if value is None:
        return None
    return context.runtime_store("artifact").resolve_pipeline_serial(value)


def require_values(selectors: dict[str, list[str]], name: str) -> list[str]:
    """Return all selector values for a required key.

    Called by: artifact command handlers that require one repeated-capable key.
    """
    values = selectors.get(name, [])
    if not values:
        raise ValueError(f"artifact {name}= is required")
    return values


def single_value(selectors: dict[str, list[str]], name: str) -> str | None:
    """Return one selector value and reject ambiguous repeats.

    Called by: artifact query/search/action helpers.
    """
    values = selectors.get(name, [])
    if len(values) > 1:
        raise ValueError(f"artifact selector {name}= may only appear once")
    return values[0] if values else None
