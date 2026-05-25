"""Domain models for HTTP header checks.

Provides typed input and result records shared by detection, finding mapping,
and command orchestration.

Used by:
- HTTP header detection code: describe probe targets and results.
- tests: construct pure model values without Bywaf runtime dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class HeaderTarget:
    """One HTTP header probe target."""

    host: str
    port: int
    use_ssl: bool


@dataclass(frozen=True, slots=True)
class HeaderProbeResult:
    """Response metadata from one HTTP header probe."""

    target: HeaderTarget
    status: int
    headers: dict[str, str] = field(default_factory=dict)
