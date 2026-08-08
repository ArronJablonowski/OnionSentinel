from __future__ import annotations

import sys
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_pcap_request_service import (  # noqa: E402
    PcapRequestServiceSources,
    request_soc_alert_pcap,
)


class FakeRow(dict):
    pass


def make_sources(**overrides):
    state = {"posts": [], "inserts": [], "candidate": {"alert_id": "a"}}

    @contextmanager
    def connect():
        yield object()

    def normalize(payload, candidate):
        return {
            "request_id": "request-1",
            "group_id": candidate["group_id"],
            "reason": payload.get("reason", "review"),
        }, ""

    def insert(conn, request):
        state["inserts"].append(request)
        return FakeRow(request_id=request["request_id"], status="pending")

    def post(path, payload):
        state["posts"].append((path, payload))
        return {"ok": True, "status": "pending", "request": payload}

    values = {
        "connect_write": connect,
        "table_exists": lambda conn, table: True,
        "read_candidate": lambda conn, group: state["candidate"],
        "normalize_request": normalize,
        "insert_request": insert,
        "post_alert_store": post,
        "alert_store_configured": True,
    }
    values.update(overrides)
    return PcapRequestServiceSources(**values), state


class PcapRequestServiceTest(unittest.TestCase):
    def test_invalid_group_is_rejected_before_io(self) -> None:
        sources, state = make_sources()
        status, payload = request_soc_alert_pcap(sources, "bad/group", {})
        self.assertEqual(status, 400)
        self.assertIn("Invalid", payload["error"])
        self.assertEqual(state["posts"], [])

    def test_production_delegates_to_alert_store(self) -> None:
        sources, state = make_sources()
        status, payload = request_soc_alert_pcap(
            sources, "ABCDEF123456", {"reason": "analyst"}
        )
        self.assertEqual(status, 202)
        self.assertEqual(payload["pcap_status_key"], "queued")
        path, sent = state["posts"][0]
        self.assertEqual(path, "/pcap/request")
        self.assertEqual(sent["group_id"], "abcdef123456")
        self.assertEqual(state["inserts"], [])

    def test_production_transport_failure_is_service_unavailable(self) -> None:
        def fail(path, payload):
            raise RuntimeError("broker unavailable")

        sources, _ = make_sources(post_alert_store=fail)
        status, payload = request_soc_alert_pcap(
            sources, "abcdef123456", {}
        )
        self.assertEqual(status, 503)
        self.assertIn("broker unavailable", payload["error"])

    def test_offline_requires_queue_schema_and_candidate(self) -> None:
        sources, _ = make_sources(
            alert_store_configured=False,
            table_exists=lambda conn, table: False,
        )
        self.assertEqual(
            request_soc_alert_pcap(sources, "abcdef123456", {})[0], 503
        )
        sources, state = make_sources(alert_store_configured=False)
        state["candidate"] = {}
        self.assertEqual(
            request_soc_alert_pcap(sources, "abcdef123456", {})[0], 404
        )

    def test_offline_normalization_error_is_bad_request(self) -> None:
        sources, _ = make_sources(
            alert_store_configured=False,
            normalize_request=lambda payload, candidate: (
                None, "timestamps required"
            ),
        )
        status, payload = request_soc_alert_pcap(
            sources, "abcdef123456", {}
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "timestamps required")

    def test_offline_inserts_and_returns_durable_row(self) -> None:
        sources, state = make_sources(alert_store_configured=False)
        status, payload = request_soc_alert_pcap(
            sources, "abcdef123456", {"reason": "offline review"}
        )
        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "pending")
        self.assertEqual(payload["request"]["request_id"], "request-1")
        self.assertEqual(state["inserts"][0]["reason"], "offline review")
        self.assertEqual(state["posts"], [])

    def test_offline_repository_failure_is_service_unavailable(self) -> None:
        def insert(conn, request):
            raise OSError("disk unavailable")

        sources, _ = make_sources(
            alert_store_configured=False,
            insert_request=insert,
        )
        status, payload = request_soc_alert_pcap(
            sources, "abcdef123456", {}
        )
        self.assertEqual(status, 503)
        self.assertIn("disk unavailable", payload["error"])


if __name__ == "__main__":
    unittest.main()
