"""Shared helpers for app dispatch tests."""


class FakeHostResult:
    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, protocol):
        return {22: {"state": "open", "name": "ssh", "reason": "syn-ack"}}


class FakePortScanner:
    def scan(self, **kwargs):
        self.kwargs = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHostResult()


class FakeNmapModule:
    PortScanner = FakePortScanner
