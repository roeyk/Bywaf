"""Management exposure rule definitions.

Used by: `management_exposure.findings_from_event()` to classify passive
service, banner, port, and web fingerprint facts as exposed management
surfaces.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureRule:
    """One passive management-surface classification rule.

    Consumed by: `management_exposure.matching_rules()` and the finding payload
    builders that turn matched rules into `finding.candidate` events.
    """

    name: str
    finding_class: str
    title: str
    severity: str
    ports: frozenset[int]
    services: frozenset[str]
    keywords: tuple[str, ...]
    recommendation: str
    port_only: bool


RULES = (
    ExposureRule(
        "docker",
        "service.management.docker_api_exposed",
        "Docker API management endpoint exposed",
        "high",
        frozenset({2375, 2376}),
        frozenset({"docker", "docker-api"}),
        ("docker api", "docker engine"),
        "Restrict Docker API access to trusted hosts, require TLS client authentication, and avoid internet exposure.",
        True,
    ),
    ExposureRule(
        "kubernetes",
        "service.management.kubernetes_api_exposed",
        "Kubernetes management endpoint exposed",
        "high",
        frozenset({6443, 10250}),
        frozenset({"kubernetes", "kubelet", "kubernetes-api"}),
        ("kubernetes", "kubelet"),
        "Restrict Kubernetes control-plane and kubelet endpoints to trusted networks and require strong authentication.",
        True,
    ),
    ExposureRule(
        "redis",
        "service.management.redis_exposed",
        "Redis service exposed",
        "medium",
        frozenset({6379}),
        frozenset({"redis"}),
        ("redis_version", "redis"),
        "Bind Redis to trusted interfaces, require authentication, and restrict access with network policy.",
        True,
    ),
    ExposureRule(
        "memcached",
        "service.management.memcached_exposed",
        "Memcached service exposed",
        "medium",
        frozenset({11211}),
        frozenset({"memcached"}),
        ("memcached",),
        "Restrict Memcached to trusted application hosts and avoid public network exposure.",
        True,
    ),
    ExposureRule(
        "elasticsearch",
        "service.management.elasticsearch_exposed",
        "Elasticsearch management endpoint exposed",
        "medium",
        frozenset({9200, 9300}),
        frozenset({"elasticsearch", "opensearch"}),
        ("elasticsearch", "opensearch"),
        "Restrict search cluster APIs to trusted networks and enforce authentication.",
        True,
    ),
    ExposureRule(
        "mongodb",
        "service.management.mongodb_exposed",
        "MongoDB service exposed",
        "medium",
        frozenset({27017}),
        frozenset({"mongodb", "mongo"}),
        ("mongodb", "mongo"),
        "Restrict MongoDB to trusted networks and require authenticated access.",
        True,
    ),
    ExposureRule(
        "grafana",
        "service.management.grafana_exposed",
        "Grafana administrative interface exposed",
        "medium",
        frozenset({3000}),
        frozenset({"grafana"}),
        ("grafana",),
        "Review whether Grafana should be reachable from this scope and enforce SSO or strong authentication.",
        False,
    ),
    ExposureRule(
        "jenkins",
        "service.management.jenkins_exposed",
        "Jenkins administrative interface exposed",
        "medium",
        frozenset({8080}),
        frozenset({"jenkins"}),
        ("jenkins",),
        "Restrict Jenkins to trusted networks and enforce strong authentication for administrative users.",
        False,
    ),
    ExposureRule(
        "kibana",
        "service.management.kibana_exposed",
        "Kibana administrative interface exposed",
        "medium",
        frozenset({5601}),
        frozenset({"kibana"}),
        ("kibana",),
        "Restrict Kibana to trusted networks and require authenticated access.",
        False,
    ),
    ExposureRule(
        "prometheus",
        "service.management.prometheus_exposed",
        "Prometheus monitoring interface exposed",
        "medium",
        frozenset({9090}),
        frozenset({"prometheus"}),
        ("prometheus",),
        "Restrict Prometheus interfaces to trusted networks and avoid exposing operational metrics publicly.",
        False,
    ),
    ExposureRule(
        "rdp",
        "service.management.rdp_exposed",
        "Remote Desktop service exposed",
        "medium",
        frozenset({3389}),
        frozenset({"rdp", "ms-wbt-server"}),
        ("remote desktop", "rdp"),
        "Restrict RDP to VPN or bastion access and require strong authentication.",
        True,
    ),
    ExposureRule(
        "winrm",
        "service.management.winrm_exposed",
        "WinRM management service exposed",
        "medium",
        frozenset({5985, 5986}),
        frozenset({"winrm"}),
        ("winrm",),
        "Restrict WinRM to administrative networks and enforce encrypted authenticated sessions.",
        True,
    ),
)


def matching_rules(port: int, evidence: str) -> list[ExposureRule]:
    """Return rules matching a port, service label, or text evidence."""
    lowered = evidence.casefold()
    matches: list[ExposureRule] = []
    for rule in RULES:
        port_match = rule.port_only and port in rule.ports
        service_match = any(service in lowered for service in rule.services)
        keyword_match = any(keyword in lowered for keyword in rule.keywords)
        if port_match or service_match or keyword_match:
            matches.append(rule)
    return matches
