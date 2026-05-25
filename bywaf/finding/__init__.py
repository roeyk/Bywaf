"""Finding payload, taxonomy, and grouping helpers.

Provides the public finding helper surface used by bundled and external
plugins to create normalized finding candidates.

Used by:
- vulnerability plugins: build finding.candidate payloads.
- reporting and grouping: normalize classes, target scope, and group keys."""

from .grouping import finding_group_key, normalized_target_scope
from .payloads import candidate_payload
from .payloads import missing_http_security_header_candidates
from .payloads import stable_finding_id
from .payloads import telnet_open_candidate
from .taxonomy import STARTER_FINDING_CLASSES, FindingClassInfo, known_finding_class, validate_finding_class

__all__ = [
    "FindingClassInfo",
    "STARTER_FINDING_CLASSES",
    "candidate_payload",
    "finding_group_key",
    "known_finding_class",
    "missing_http_security_header_candidates",
    "normalized_target_scope",
    "stable_finding_id",
    "telnet_open_candidate",
    "validate_finding_class",
]
