"""Curated passive vulnerable-version indicator rules.

Used by:
- bundled plugin providers and commandlets that publish or consume framework events.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VersionIndicatorRule:
    """One passive vulnerable-version indicator rule.

    Constructed by: the static `RULES` table in this module.
    Used by: `matching_rules()` and technology indicator finding synthesis.
    """

    name: str
    product: str
    versions: tuple[str, ...]
    finding_class: str
    title: str
    severity: str
    identifiers: dict[str, list[str]]
    recommendation: str


RULES = (
    VersionIndicatorRule(
        name="apache-httpd-2.4.49",
        product="apache httpd",
        versions=("2.4.49",),
        finding_class="technology.version.apache_httpd_2_4_49_indicator",
        title="Apache httpd 2.4.49 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2021-41773"]},
        recommendation=(
            "Confirm the Apache httpd build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="apache-httpd-2.4.50",
        product="apache httpd",
        versions=("2.4.50",),
        finding_class="technology.version.apache_httpd_2_4_50_indicator",
        title="Apache httpd 2.4.50 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2021-42013"]},
        recommendation=(
            "Confirm the Apache httpd build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="nginx-1.3.9-to-1.4.0",
        product="nginx",
        versions=("1.3.9", "1.3.10", "1.3.11", "1.3.12", "1.3.13", "1.3.14", "1.3.15", "1.3.16", "1.4.0"),
        finding_class="technology.version.nginx_1_3_9_to_1_4_0_indicator",
        title="nginx 1.3.9-1.4.0 version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2013-2028"]},
        recommendation=(
            "Confirm the nginx build and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="microsoft-iis-6.0",
        product="microsoft iis",
        versions=("6.0",),
        finding_class="technology.version.microsoft_iis_6_0_indicator",
        title="Microsoft IIS 6.0 version indicator observed",
        severity="critical",
        identifiers={"cve": ["CVE-2017-7269"]},
        recommendation=(
            "Confirm the IIS version, Windows Server release, and WebDAV exposure "
            "with asset owners, then retire or isolate the service if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="openssl-1.0.1-to-1.0.1f",
        product="openssl",
        versions=("1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"),
        finding_class="technology.version.openssl_1_0_1_to_1_0_1f_indicator",
        title="OpenSSL 1.0.1-1.0.1f version indicator observed",
        severity="high",
        identifiers={"cve": ["CVE-2014-0160"]},
        recommendation=(
            "Confirm the OpenSSL build options and patch level with asset owners, "
            "then upgrade to a fixed vendor-supported release if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="vsftpd-2.3.4",
        product="vsftpd",
        versions=("2.3.4",),
        finding_class="technology.version.vsftpd_2_3_4_indicator",
        title="vsftpd 2.3.4 version indicator observed",
        severity="critical",
        identifiers={"cve": ["CVE-2011-2523"]},
        recommendation=(
            "Confirm the vsftpd package source and deployment date with asset owners, "
            "then replace the service with a trusted fixed build if applicable."
        ),
    ),
    VersionIndicatorRule(
        name="unrealircd-3.2.8.1",
        product="unrealircd",
        versions=("3.2.8.1",),
        finding_class="technology.version.unrealircd_3_2_8_1_indicator",
        title="UnrealIRCd 3.2.8.1 version indicator observed",
        severity="critical",
        identifiers={"cve": ["CVE-2010-2075"]},
        recommendation=(
            "Confirm the UnrealIRCd package source and build provenance with asset owners, "
            "then replace the service with a trusted fixed build if applicable."
        ),
    ),
)

APACHE_VERSION_RE = re.compile(r"\b(?:apache(?:\s+httpd)?|httpd|apache)/(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE)
NGINX_VERSION_RE = re.compile(r"\bnginx/(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE)
IIS_VERSION_RE = re.compile(r"\b(?:microsoft-)?iis/(?P<version>\d+\.\d+)\b", re.IGNORECASE)
OPENSSL_VERSION_RE = re.compile(r"\bopenssl/(?P<version>\d+\.\d+\.\d+[a-z]?)\b", re.IGNORECASE)
VSFTPD_VERSION_RE = re.compile(r"\bvsftpd\s+(?P<version>\d+\.\d+\.\d+)\b", re.IGNORECASE)
UNREALIRCD_VERSION_RE = re.compile(r"\bunrealircd[-\s/]?(?P<version>\d+\.\d+\.\d+\.\d+)\b", re.IGNORECASE)

# Dispatch table used by `matching_rules()` to extract product-specific
# version tokens without a long product-name branch ladder.
VERSION_PATTERNS = {
    "apache httpd": APACHE_VERSION_RE,
    "nginx": NGINX_VERSION_RE,
    "microsoft iis": IIS_VERSION_RE,
    "openssl": OPENSSL_VERSION_RE,
    "vsftpd": VSFTPD_VERSION_RE,
    "unrealircd": UNREALIRCD_VERSION_RE,
}


def matching_rules(evidence: str) -> list[VersionIndicatorRule]:
    """Return rules matching passive evidence text.

    Called by: `technology_indicators.findings_from_event()`.
    """
    observed_versions = {
        product: {match.group("version").lower() for match in pattern.finditer(evidence)}
        for product, pattern in VERSION_PATTERNS.items()
    }
    return [
        rule
        for rule in RULES
        if any(version.lower() in observed_versions.get(rule.product, set()) for version in rule.versions)
    ]
