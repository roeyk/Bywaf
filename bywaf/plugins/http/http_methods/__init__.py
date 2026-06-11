"""HTTP method inspection commandlet."""

from __future__ import annotations

import http.client
from collections.abc import Iterable

from bywaf.event import Event
from bywaf.finding import candidate_payload
from bywaf.plugin import CommandContext, Commandlet, CommandletBase, commandlet, option, parse_bool
from bywaf.plugins.http.http_targets import (
    HttpTarget as MethodTarget,
    build_url as build_url,
    choose_scheme as choose_scheme,
    http_target_from_port_event,
    http_target_from_text,
    http_targets,
    normalize_path as normalize_path,
    split_host_port as split_host_port,
)
from bywaf.plugins.target_policy import filter_targets_by_host

DEFAULTS = {"path": "/", "scheme": "auto", "silent": "false", "timeout": 5}

# Classification tables for method-risk promotion.
#
# Used by: `method_findings()`, which treats write-capable methods and WebDAV
# methods as separate finding classes even though their operational risk can
# overlap.
WRITE_METHODS = ("PUT", "PATCH", "DELETE")
WEBDAV_METHODS = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


@commandlet(
    name="http_methods",
    description="Probe HTTP OPTIONS and report risky allowed methods.",
    usage="http_methods [options] [target ...]",
    examples=(
        "http_methods https://example.test/",
        "hostscanner 127.0.0.1 | portscanner port=80,443 | http_methods",
    ),
)
@option("path", "request path", "/")
@option("scheme", "scheme override", "auto", ("auto", "http", "https"))
@option("silent", "suppress probe alerts", "false")
@option("timeout", "request timeout seconds", "5")
class HttpMethods(CommandletBase):
    """Probe OPTIONS and emit method posture facts plus candidates.

    Called by: PluginRegistry/runner dispatch for the `http_methods`
    commandlet.

    Emits: plugin-owned `http.methods` facts and `finding.candidate` events
    for risky allowed methods.
    """

    def run(
        self,
        context: CommandContext,
        args: list[str],
        input_events: Iterable[Event],
    ):
        """Probe explicit URLs/hosts or HTTP-looking pipeline ports.

        Called by: the Bywaf runner through `CommandletBase.run()`.
        """
        parser = self.parser()
        # Add positional targets and runtime options to the argparse parser
        # that executes this commandlet invocation.
        parser.add_argument("targets", nargs="*")
        parser.add_argument("--path", default=self.var_default(context, "path", "/"))
        parser.add_argument("--scheme", choices=("auto", "http", "https"), default=self.var_default(context, "scheme", "auto"))
        parser.add_argument("-s", "--silent", action="store_true", default=self.var_default(context, "silent", False, cast=parse_bool))
        parser.add_argument("--timeout", type=float, default=self.var_default(context, "timeout", 5, cast=float))
        # Parse command-line arguments into concrete runtime values.
        parsed = parser.parse_args(args)

        # Resolve direct or pipeline targets, then apply the global target
        # scope policy by comparing each MethodTarget by host.
        targets = filter_targets_by_host(
            context,
            method_targets(parsed.targets, input_events, parsed.scheme, parsed.path),
            lambda target: target.host,
        )
        for target in targets:
            # Record actual runtime use of the declared network capability.
            context.audit_capability("network.connect")

            # Send OPTIONS and normalize the response into a loose result dict.
            result = probe_methods(target, timeout=parsed.timeout)

            # Convert the probe result into the plugin-owned `http.methods`
            # event payload that the framework persists from yielded output.
            payload = result_payload(target, result)

            # Promote risky method combinations to finding candidates before
            # yielding the method fact.
            for finding in method_findings(payload):
                context.events.publish("finding.candidate", finding)
            methods = methods_from_payload(payload)

            # Request compact operator feedback for interactive runs. The
            # structured event and finding candidates remain the primary data.
            context.alert(
                f"observed HTTP methods {target.url} methods={','.join(methods) or 'unknown'}",
                silent=parsed.silent,
            )
            yield payload

    def targets(self, targets, scheme, path, input_events):
        """Resolve target tuples for compatibility tests/callers.

        Called by: tests and older callers that expect tuple output rather
        than `MethodTarget` objects.
        """
        # Convert the shared HTTP target model back to the historical tuple
        # shape exposed by this commandlet helper.
        return [
            (target.host, target.port, target.scheme, target.path)
            for target in method_targets(list(targets or []), input_events, scheme, path)
        ]


def method_targets(
    targets: list[str],
    input_events: Iterable[Event],
    scheme: str,
    path: str,
) -> list[MethodTarget]:
    """Resolve method-probe targets from arguments or upstream port events.

    Called by: `HttpMethods.run()` and `HttpMethods.targets()`.
    """
    # Delegate URL/host/port parsing to the shared HTTP target helper so HTTP
    # plugins use consistent defaults and pipeline conversion.
    return http_targets(targets, input_events, scheme, path)


def target_from_port_event(event: Event, scheme: str, path: str) -> MethodTarget:
    """Convert one `port.open` event into a method probe target.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_port_event(event, scheme, path)


def target_from_text(target: str, scheme: str, path: str) -> MethodTarget:
    """Parse URL, host, or host:port text into a MethodTarget.

    Re-exported for tests and compatibility imports.
    """
    return http_target_from_text(target, scheme, path)


def probe_methods(target: MethodTarget, *, timeout: float) -> dict[str, object]:
    """Perform one OPTIONS request and return method metadata.

    Called by: `HttpMethods.run()` once per scoped target.
    """
    # Pick the stdlib connection class that matches the resolved target scheme.
    connection_class = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection

    # Open an HTTP(S) connection to the target host and port.
    connection = connection_class(target.host, target.port, timeout=timeout)
    try:
        # Send an OPTIONS request to the target path.
        connection.request("OPTIONS", target.path)

        # Read the server's OPTIONS response.
        response = connection.getresponse()

        # Prefer the standard Allow header, then fall back to the older Public
        # header used by some servers.
        allow = response.getheader("Allow") or ""
        public = response.getheader("Public") or ""

        # Parse the selected header into sorted uppercase method tokens.
        methods = normalize_methods(allow or public)
        return {
            "ok": True,
            "status": response.status,
            "reason": response.reason,
            "allow": allow,
            "public": public,
            "methods": methods,
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Preserve a structured error payload so one failed target does not
        # abort the rest of the commandlet run.
        return {"ok": False, "error": str(exc), "methods": []}
    finally:
        # Always release the socket-like connection object after probing.
        connection.close()


def normalize_methods(value: str) -> list[str]:
    """Return normalized HTTP method tokens from an Allow/Public header.

    Called by: `probe_methods()` after reading Allow/Public.
    """
    # Treat semicolons as separators too; some servers return non-standard
    # method lists, and this keeps parsing permissive without accepting
    # non-alpha tokens.
    methods = {
        token.strip().upper()
        for token in value.replace(";", ",").split(",")
        if token.strip().isalpha()
    }
    return sorted(methods)


def result_payload(target: MethodTarget, result: dict[str, object]) -> dict[str, object]:
    """Return the plugin-owned `http.methods` fact payload.

    Called by: `HttpMethods.run()` before yielding the fact.
    """
    # Combine stable target fields with probe response fields in the event
    # schema shape declared by the plugin manifest.
    return {
        "url": target.url,
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "path": target.path,
        "status": result.get("status"),
        "methods": result.get("methods", []),
        "allow": result.get("allow", ""),
        "public": result.get("public", ""),
        "error": result.get("error", ""),
    }


def method_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Promote risky allowed methods into normalized finding candidates.

    Called by: `HttpMethods.run()` after one `http.methods` payload is built.
    """
    # Accept a loose payload because this helper may also be used by analysis
    # or tests reading persisted event dictionaries.
    methods = methods_from_payload(payload)
    findings: list[dict[str, object]] = []
    if "TRACE" in methods:
        # TRACE is a distinct browser/proxy risk and gets its own finding even
        # when other risky methods are also present.
        findings.append(
            candidate_payload(
                title="HTTP TRACE method enabled",
                finding_class="web.method.trace_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-16"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed HTTP methods: {', '.join(methods)}.",
                recommendation="Disable TRACE unless there is a documented operational requirement.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    write_methods = [method for method in WRITE_METHODS if method in methods]
    if write_methods:
        # PUT/PATCH/DELETE imply write-capable behavior and should be grouped
        # separately from TRACE and WebDAV findings.
        findings.append(
            candidate_payload(
                title="HTTP write-capable methods enabled",
                finding_class="web.method.write_methods_enabled",
                severity="medium",
                confidence="medium",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A01:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed write-capable HTTP methods: {', '.join(write_methods)}.",
                recommendation="Disable PUT, PATCH, and DELETE unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    webdav_methods = [method for method in WEBDAV_METHODS if method in methods]
    if webdav_methods:
        # WebDAV methods often imply additional server-side file operation
        # surface, so they remain a distinct finding class.
        findings.append(
            candidate_payload(
                title="WebDAV HTTP methods enabled",
                finding_class="web.method.webdav_enabled",
                severity="medium",
                confidence="medium",
                confidence_basis="safe_probe",
                finding_scope="web_origin",
                target=target_payload(payload),
                identifiers={"cwe": ["CWE-650"], "owasp": ["A05:2021"]},
                affected=[{"url": str(payload["url"])}],
                evidence=f"{payload['url']} allowed WebDAV HTTP methods: {', '.join(webdav_methods)}.",
                recommendation="Disable WebDAV methods unless they are required and access-controlled.",
                source={"tool": "http_methods", "topic": "http.methods"},
            )
        )
    return findings


def methods_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Return normalized method names from a loose event payload.

    Called by: `HttpMethods.run()` and `method_findings()`.
    """
    value = payload.get("methods", ())
    if not isinstance(value, list | tuple):
        return ()

    # Convert stored values back to uppercase method names for matching and
    # display, tolerating loose persisted payloads.
    return tuple(str(method).upper() for method in value if method)


def target_payload(payload: dict[str, object]) -> dict[str, str]:
    """Return normalized target details for finding candidates.

    Called by: `method_findings()` when packaging candidate payloads.
    """
    # Finding payloads expect string target fields for stable grouping keys.
    return {
        "scheme": str(payload["scheme"]),
        "host": str(payload["host"]),
        "port": str(payload["port"]),
        "path": str(payload["path"]),
    }


def plugin() -> Commandlet:
    """Return the commandlet object loaded by PluginRegistry."""
    return HttpMethods()
