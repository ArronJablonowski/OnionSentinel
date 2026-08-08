from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_pcap_request_policy import (  # noqa: E402
    PcapRequestPolicySources,
    bounded_int,
    normalize_pcap_request,
    pcap_request_id,
)


class PcapRequestPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = PcapRequestPolicySources(
            normalize_timestamp=lambda value: (
                str(value).strip().replace(" ", "T")
                if str(value or "").strip() != "invalid"
                else ""
            )
        )
        self.candidate = {
            "alert_id": "alert-1",
            "group_id": "abcdef123456",
            "group_key": "group-key",
            "first_seen": "2026-08-07 12:00:00Z",
            "last_seen": "2026-08-07 12:01:00Z",
            "source_ip": "192.0.2.10",
            "source_port": 12345,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "transport_protocol": "TCP",
        }

    def test_bounded_integer_handles_invalid_and_extreme_values(self) -> None:
        self.assertEqual(bounded_int("bad", 120, 30, 300), 120)
        self.assertEqual(bounded_int(float("inf"), 120, 30, 300), 120)
        self.assertEqual(bounded_int(-1, 120, 30, 300), 30)
        self.assertEqual(bounded_int(999, 120, 30, 300), 300)

    def test_request_id_is_deterministic_and_order_sensitive_by_contract(self) -> None:
        seed = {"alert_id": "a", "reason": "review"}
        self.assertEqual(pcap_request_id(seed), pcap_request_id(seed))
        self.assertNotEqual(
            pcap_request_id(seed),
            pcap_request_id({"alert_id": "a", "reason": "different"}),
        )

    def test_candidate_is_normalized_with_analyst_overrides(self) -> None:
        request, error = normalize_pcap_request(
            self.sources,
            {
                "reason": " analyst request ",
                "requested_by": "unit-test",
                "destination_port": 70000,
                "max_window_seconds": 10,
                "require_source_port": True,
            },
            self.candidate,
        )
        self.assertEqual(error, "")
        self.assertEqual(request["first_seen"], "2026-08-07T12:00:00Z")
        self.assertEqual(request["transport_protocol"], "tcp")
        self.assertEqual(request["destination_port"], 65535)
        self.assertEqual(request["max_window_seconds"], 30)
        self.assertEqual(request["reason"], "analyst request")
        self.assertTrue(request["require_source_port"])
        self.assertEqual(len(request["request_id"]), 16)

    def test_default_metadata_and_zero_ports_are_preserved_as_null(self) -> None:
        request, _ = normalize_pcap_request(
            self.sources,
            {"source_port": 0, "destination_port": "bad"},
            self.candidate,
        )
        self.assertIsNone(request["source_port"])
        self.assertIsNone(request["destination_port"])
        self.assertEqual(request["requested_by"], "dashboard")
        self.assertEqual(request["reason"], "SOC analyst requested PCAP evidence")

    def test_missing_endpoints_are_rejected(self) -> None:
        for field in ("source_ip", "destination_ip"):
            candidate = dict(self.candidate)
            candidate[field] = ""
            request, error = normalize_pcap_request(
                self.sources, {}, candidate
            )
            self.assertIsNone(request)
            self.assertIn("source and destination", error)

    def test_missing_or_invalid_times_are_rejected(self) -> None:
        candidate = dict(self.candidate)
        candidate.update({"first_seen": "invalid", "last_seen": "invalid"})
        request, error = normalize_pcap_request(self.sources, {}, candidate)
        self.assertIsNone(request)
        self.assertIn("first_seen and last_seen", error)

    def test_text_fields_are_bounded(self) -> None:
        request, _ = normalize_pcap_request(
            self.sources,
            {
                "alert_id": "a" * 600,
                "group_key": "g" * 600,
                "reason": "r" * 300,
                "capture_file": "c" * 600,
                "community_id": "i" * 200,
            },
            self.candidate,
        )
        self.assertEqual(len(request["alert_id"]), 512)
        self.assertEqual(len(request["group_key"]), 512)
        self.assertEqual(len(request["reason"]), 240)
        self.assertEqual(len(request["capture_file"]), 512)
        self.assertEqual(len(request["community_id"]), 128)


if __name__ == "__main__":
    unittest.main()
