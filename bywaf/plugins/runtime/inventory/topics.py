"""Topic groups consumed by operator inventory commandlets.

Used by:
- `runtime.inventory`: assigns each inventory commandlet the event topics it
  needs to build its operator view.
- `runtime.inventory.scope`: receives these groups when selecting events from
  jobs, pipelines, steps, or the whole project.
"""

HOST_TOPICS = ("host.found", "name.resolved", "port.open", "http.endpoint", "service.detected", "finding.candidate")
"""Topics needed to build the host-centric inventory view."""

SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")
"""Topics needed to build the service-centric inventory view."""

WEB_TOPICS = (
    "http.endpoint",
    "http.path",
    "web.fingerprint",
    "web.waf.detected",
    "web.screenshotted_host",
    "finding.candidate",
)
"""Topics needed to build the web endpoint inventory view."""

WAF_TOPICS = ("web.waf.detected",)
"""Topics needed to build the WAF inventory view."""

SHARE_TOPICS = ("smb.share.found",)
"""Topics needed to build the SMB share inventory view."""

ROUTE_TOPICS = ("network.route.hop",)
"""Topics needed to build the route inventory view."""

CERT_TOPICS = ("tls.certificate",)
"""Topics needed to build the certificate inventory view."""

BANNER_TOPICS = ("tcp.banner",)
"""Topics needed to build the TCP banner inventory view."""

PATH_TOPICS = ("http.path",)
"""Topics needed to build the discovered HTTP path inventory view."""

SCREENSHOT_TOPICS = ("web.screenshotted_host",)
"""Topics needed to build the screenshot inventory view."""
