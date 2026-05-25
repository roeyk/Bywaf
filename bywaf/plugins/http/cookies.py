"""HTTP cookie parsing and persistence helpers.

Provides lightweight cookie jar loading, saving, and header formatting for HTTP
commandlets that need session continuity.

Used by:
- HTTP plugins: share cookies across probes and requests.
- HTTP-focused tests: validate cookie file behavior."""


from __future__ import annotations

import http.cookiejar
import sqlite3
from pathlib import Path


def load_cookie_jar(
    cookie_file: str | None = None,
    firefox_profile: str | None = None,
) -> http.cookiejar.CookieJar:
    """Load cookies from optional Netscape and Firefox sources."""
    jar = http.cookiejar.CookieJar()
    # Sources are additive so users can combine exported cookies and a browser
    # profile when a target application needs session continuity.
    if cookie_file:
        load_netscape_cookie_file(Path(cookie_file), jar)
    if firefox_profile:
        load_firefox_cookies(Path(firefox_profile), jar)
    return jar


def load_netscape_cookie_file(path: Path, jar: http.cookiejar.CookieJar) -> None:
    """Merge a Netscape-format cookie file into an existing jar."""
    mozilla = http.cookiejar.MozillaCookieJar(str(path))
    mozilla.load(ignore_discard=True, ignore_expires=True)
    for cookie in mozilla:
        jar.set_cookie(cookie)


def load_firefox_cookies(profile: Path, jar: http.cookiejar.CookieJar) -> None:
    """Read Firefox cookies.sqlite without mutating the browser profile."""
    db_path = profile / "cookies.sqlite" if profile.is_dir() else profile
    # immutable=1 tells SQLite this is a read-only snapshot-style open; Firefox
    # remains the owner of the real profile database.
    uri = f"file:{db_path}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    try:
        # Copy rows into a normal CookieJar. After this point HTTP tools do not
        # hold a live connection to the browser profile database.
        rows = conn.execute(
            """
            SELECT host, path, isSecure, expiry, name, value
            FROM moz_cookies
            """
        )
        for host, path, secure, expiry, name, value in rows:
            jar.set_cookie(
                http.cookiejar.Cookie(
                    version=0,
                    name=name,
                    value=value,
                    port=None,
                    port_specified=False,
                    domain=host,
                    domain_specified=host.startswith("."),
                    domain_initial_dot=host.startswith("."),
                    path=path,
                    path_specified=True,
                    secure=bool(secure),
                    expires=int(expiry) if expiry else None,
                    discard=False,
                    comment=None,
                    comment_url=None,
                    rest={},
                    rfc2109=False,
                )
            )
    finally:
        conn.close()
