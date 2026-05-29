"""Typed objects for framework-known shared event contracts.

Provides small dataclasses that plugin authors can import instead of defining
their own wrappers around common shared event payloads.

Used by:
- plugin authors: deserialize shared events into typed objects.
- tests and docs: demonstrate object-first contract handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .event_contracts import ContractObject


@dataclass(frozen=True)
class HostFound(ContractObject):
    """A host observed alive or otherwise reachable."""

    __topic__ = "host.found"

    host: str
    ip: str | None = None
    name: str | None = None
    status: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class NameResolved(ContractObject):
    """One hostname-to-address resolution fact."""

    __topic__ = "name.resolved"

    name: str
    host: str
    resolver: str | None = None


@dataclass(frozen=True)
class OpenPort(ContractObject):
    """A network port observed open on a host."""

    __topic__ = "port.open"

    host: str
    port: int
    protocol: str
    state: str | None = None
    service: str | None = None
    reason: str | None = None
    scanner: str | None = None


@dataclass(frozen=True)
class HttpEndpoint(ContractObject):
    """A reachable HTTP or HTTPS endpoint."""

    __topic__ = "http.endpoint"

    url: str
    host: str
    port: int
    scheme: str
    status: int | None = None
    method: str | None = None
    server: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class SmbShareFound(ContractObject):
    """An SMB share observed on a host."""

    __topic__ = "smb.share.found"

    host: str
    share: str
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    access: str | None = None
    authenticated: bool | None = None
    remark: str | None = None


@dataclass(frozen=True)
class ArtifactAttached(ContractObject):
    """Artifact metadata attached to runtime provenance."""

    __topic__ = "artifact.attached"

    artifact_id: str
    name: str
    content_type: str
    sha256: str
    size: int
    commandlet: str | None = None
    job_id: Any = None
    pipeline_id: str | None = None
    command_run_id: str | None = None
    note: str | None = None


__all__ = [
    "ArtifactAttached",
    "HostFound",
    "HttpEndpoint",
    "NameResolved",
    "OpenPort",
    "SmbShareFound",
]
