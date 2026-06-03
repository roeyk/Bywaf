"""Finding class taxonomy helpers.

Provides the Bywaf finding-class naming convention plus starter registry
entries mapped to familiar external taxonomies such as CWE and OWASP.

Used by:
- finding payload helpers: validate normalized candidate classes.
- report and grouping tests: keep class names stable and familiar."""

from __future__ import annotations

import re
from dataclasses import dataclass


FINDING_CLASS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)*$")


@dataclass(frozen=True, slots=True)
class FindingClassInfo:
    """Metadata for one known finding class."""

    name: str
    description: str
    identifiers: dict[str, tuple[str, ...]]


STARTER_FINDING_CLASSES: dict[str, FindingClassInfo] = {
    # This is a starter vocabulary, not a closed enum. Unknown but syntactically
    # valid classes are allowed so third-party plugins can grow new domains.
    "web.header.missing_hsts": FindingClassInfo(
        "web.header.missing_hsts",
        "Missing Strict-Transport-Security header.",
        {"cwe": ("CWE-319",), "owasp": ("A02:2021",)},
    ),
    "web.header.missing_csp": FindingClassInfo(
        "web.header.missing_csp",
        "Missing Content-Security-Policy header.",
        {"cwe": ("CWE-693",), "owasp": ("A05:2021",)},
    ),
    "web.header.missing_x_content_type_options": FindingClassInfo(
        "web.header.missing_x_content_type_options",
        "Missing X-Content-Type-Options header.",
        {"cwe": ("CWE-693",), "owasp": ("A05:2021",)},
    ),
    "web.exposure.git_config": FindingClassInfo(
        "web.exposure.git_config",
        "Exposed Git repository configuration metadata.",
        {"cwe": ("CWE-538",), "owasp": ("A05:2021",)},
    ),
    "web.exposure.source_control_metadata": FindingClassInfo(
        "web.exposure.source_control_metadata",
        "Exposed source-control metadata.",
        {"cwe": ("CWE-538",), "owasp": ("A05:2021",)},
    ),
    "web.exposure.source_map": FindingClassInfo(
        "web.exposure.source_map",
        "Exposed JavaScript source map.",
        {"cwe": ("CWE-538",), "owasp": ("A05:2021",)},
    ),
    "web.exposure.directory_listing": FindingClassInfo(
        "web.exposure.directory_listing",
        "Directory listing exposes application content.",
        {"cwe": ("CWE-548",), "owasp": ("A05:2021",)},
    ),
    "web.xss.reflected": FindingClassInfo(
        "web.xss.reflected",
        "Reflected cross-site scripting.",
        {"cwe": ("CWE-79",), "owasp": ("A03:2021",)},
    ),
    "web.auth.default_credentials": FindingClassInfo(
        "web.auth.default_credentials",
        "Default credentials accepted by an application.",
        {"cwe": ("CWE-798",), "owasp": ("A07:2021",)},
    ),
    "service.telnet.exposed": FindingClassInfo(
        "service.telnet.exposed",
        "Telnet service exposed on a target.",
        {"cwe": ("CWE-319",), "owasp": ("A02:2021",)},
    ),
    "service.management.redis_exposed": FindingClassInfo(
        "service.management.redis_exposed",
        "Redis service exposed on a target.",
        {"cwe": ("CWE-284",), "owasp": ("A01:2021",)},
    ),
    "service.management.docker_api_exposed": FindingClassInfo(
        "service.management.docker_api_exposed",
        "Docker API management endpoint exposed on a target.",
        {"cwe": ("CWE-284",), "owasp": ("A01:2021",)},
    ),
    "service.management.kubernetes_api_exposed": FindingClassInfo(
        "service.management.kubernetes_api_exposed",
        "Kubernetes management endpoint exposed on a target.",
        {"cwe": ("CWE-284",), "owasp": ("A01:2021",)},
    ),
    "service.tls.weak_protocol": FindingClassInfo(
        "service.tls.weak_protocol",
        "Weak TLS protocol version enabled.",
        {"cwe": ("CWE-327",), "owasp": ("A02:2021",)},
    ),
    "cloud.aws.s3.public_bucket": FindingClassInfo(
        "cloud.aws.s3.public_bucket",
        "AWS S3 bucket allows public access.",
        {"cwe": ("CWE-284",), "owasp": ("A01:2021",)},
    ),
    "repo.secret.api_key": FindingClassInfo(
        "repo.secret.api_key",
        "API key or token exposed in repository content.",
        {"cwe": ("CWE-798",), "owasp": ("A02:2021",)},
    ),
}


def validate_finding_class(name: str) -> str:
    """Return a normalized finding class name or raise ValueError."""
    # Finding classes use dots, like event topics and capabilities. Catalog
    # paths and user variable scopes intentionally use different separators.
    if not isinstance(name, str) or not FINDING_CLASS_RE.fullmatch(name):
        raise ValueError(
            "finding_class must use lowercase dot-separated tokens, "
            "for example web.header.missing_hsts"
        )
    return name


def known_finding_class(name: str) -> bool:
    """Return whether one class is in Bywaf's starter registry."""
    return name in STARTER_FINDING_CLASSES
