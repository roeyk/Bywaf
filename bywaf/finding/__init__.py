"""Finding payload, taxonomy, and grouping helpers.

Provides the public finding helper surface used by bundled and external
plugins to create normalized finding candidates.

Used by:
- vulnerability plugins: build finding.candidate payloads.
- reporting and grouping: normalize classes, target scope, and group keys."""

from .grouping import finding_group_key, normalized_target_scope
from .payloads import candidate_payload
from .payloads import confirmed_payload
from .payloads import missing_http_sec_headers
from .payloads import stable_finding_id
from .payloads import telnet_open_candidate
from .severity import SEVERITY_CLASS_ORDER, severity_class
from .subjects import SUBJECTS, infer_subjects, subject_value, validate_subject
from .taxonomy import STARTER_FINDING_CLASSES, FindingClassInfo, known_finding_class, validate_finding_class

__all__ = [
    "FindingClassInfo",
    "SUBJECTS",
    "STARTER_FINDING_CLASSES",
    "SEVERITY_CLASS_ORDER",
    "candidate_payload",
    "confirmed_payload",
    "finding_group_key",
    "infer_subjects",
    "known_finding_class",
    "missing_http_sec_headers",
    "normalized_target_scope",
    "severity_class",
    "stable_finding_id",
    "subject_value",
    "telnet_open_candidate",
    "validate_subject",
    "validate_finding_class",
]
