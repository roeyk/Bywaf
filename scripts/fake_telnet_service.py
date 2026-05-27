#!/usr/bin/env python3
"""Serve a tiny Telnet-like banner for local portscanner tests.

Provides a harmless loopback service that is useful when validating nmap
service detection and Bywaf's Telnet finding promotion logic without running a
real Telnet daemon.

Used by:
- manual testing: scan a nonstandard Telnet-like port with network/portscanner.
- reporting checks: create a controlled finding.candidate event for report.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time


DEFAULT_BANNER = b"\xff\xfb\x01\xff\xfb\x03Telnet server ready\r\nlogin: "


def handle_client(conn: socket.socket, banner: bytes, hold_seconds: float) -> None:
    """Send one banner and hold the connection briefly for nmap probes."""
    try:
        conn.sendall(banner)
        time.sleep(hold_seconds)
    finally:
        conn.close()


def main() -> None:
    """Bind a TCP listener and serve the same banner to every connection."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2323)
    parser.add_argument("--hold-seconds", type=float, default=3.0)
    args = parser.parse_args()

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(20)

    print(f"fake telnet listening on {args.host}:{args.port}", flush=True)

    while True:
        conn, addr = sock.accept()
        print(f"connection from {addr[0]}:{addr[1]}", flush=True)
        thread = threading.Thread(
            target=handle_client,
            args=(conn, DEFAULT_BANNER, args.hold_seconds),
            daemon=True,
        )
        thread.start()


if __name__ == "__main__":
    main()
