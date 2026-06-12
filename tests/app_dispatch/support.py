"""Shared helpers for app dispatch tests.

Coverage focus: shared fixtures and test doubles for app dispatch tests.
"""


class FakeHostResult:
    """Test double used by this module's regression cases."""
    def state(self):
        """Test helper for state."""
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    """Test double used by this module's regression cases."""
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    """Test double used by this module's regression cases."""
    PortScanner = FakePortScanner
