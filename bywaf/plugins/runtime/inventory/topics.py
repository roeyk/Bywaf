"""Topic groups consumed by operator inventory commandlets.

Used by:
- `runtime.inventory`: assigns each inventory commandlet the event topics it
  needs to build its operator view.
- `runtime.inventory.scope`: receives these groups when selecting events from
  jobs, pipelines, steps, or the whole project.
"""

HOST_TOPICS = ("host.found", "name.resolved", "port.open", "http.endpoint", "service.detected", "finding.candidate")
SERVICE_TOPICS = ("port.open", "service.detected", "http.endpoint", "tcp.banner", "tls.certificate")
WEB_TOPICS = (
    "http.endpoint",
    "http.path",
    "web.fingerprint",
    "web.waf.detected",
    "web.screenshotted_host",
    "finding.candidate",
)
WAF_TOPICS = ("web.waf.detected",)
SHARE_TOPICS = ("smb.share.found",)
ROUTE_TOPICS = ("network.route.hop",)
CERT_TOPICS = ("tls.certificate",)
BANNER_TOPICS = ("tcp.banner",)
PATH_TOPICS = ("http.path",)
SCREENSHOT_TOPICS = ("web.screenshotted_host",)
