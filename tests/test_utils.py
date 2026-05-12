from pathlib import Path
import tempfile
import unittest

from bywaf.utils import (
    complete_path,
    expand_ipv4_range,
    host_candidates,
    parse_octet_range,
    parse_ports,
    split_pipeline,
)


class UtilsTests(unittest.TestCase):
    def test_split_pipeline_detects_background(self):
        parts, background = split_pipeline("hostscanner 127.0.0.1 | portscanner &")
        self.assertEqual(parts, ["hostscanner 127.0.0.1", "portscanner"])
        self.assertTrue(background)

    def test_parse_ports_supports_ranges_and_dedupes(self):
        self.assertEqual(parse_ports("80,443,80,8000-8002"), (80, 443, 8000, 8001, 8002))

    def test_parse_ports_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_host_candidates_expands_cidr(self):
        self.assertEqual(host_candidates("127.0.0.0/30"), ("127.0.0.1", "127.0.0.2"))

    def test_host_candidates_keeps_hostname(self):
        self.assertEqual(host_candidates("example.test"), ("example.test",))

    def test_host_candidates_expands_last_octet_range(self):
        self.assertEqual(
            host_candidates("192.168.0.1-3"),
            ("192.168.0.1", "192.168.0.2", "192.168.0.3"),
        )

    def test_host_candidates_expands_multiple_octet_ranges(self):
        self.assertEqual(
            host_candidates("192.168.1-2.1-2"),
            ("192.168.1.1", "192.168.1.2", "192.168.2.1", "192.168.2.2"),
        )

    def test_expand_ipv4_range_rejects_descending_octet_range(self):
        with self.assertRaises(ValueError):
            expand_ipv4_range("192.168.3-1.1")

    def test_parse_octet_range_rejects_bad_octet(self):
        with self.assertRaises(ValueError):
            parse_octet_range("256")

    def test_complete_path_returns_matching_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "alpha.txt").write_text("x")
            Path(tmp, "beta.txt").write_text("x")
            self.assertEqual(complete_path("al", tmp), ["alpha.txt"])


if __name__ == "__main__":
    unittest.main()
