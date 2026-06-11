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
    """One HTTP header probe target.

    Constructed by: `command.header_targets()`.

    Used by: `detect.fetch_headers()` and finding payload construction.
    """

    # Keep this model protocol-level instead of URL-level so command.py can
    # accept both direct host args and upstream port.open/http.endpoint facts.
    host: str
    port: int
    use_ssl: bool


@dataclass(frozen=True, slots=True)
class HeaderProbeResult:
    """Response metadata from one HTTP header probe.

    Constructed by: `detect.fetch_headers()`.

    Used by: `findings.result_payload()` and
    `findings.missing_security_header_candidates()`.
    """

    # headers stays a plain dict so detect.py remains independently testable
    # without Bywaf event objects or HTTP client response objects.
    target: HeaderTarget
    status: int
    headers: dict[str, str] = field(default_factory=dict)
