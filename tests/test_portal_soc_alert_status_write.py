from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_alert_status_write import (  # noqa: E402
    SocAlertStatusWriteSources,
    update_soc_alert_status,
)


class StoreError(RuntimeError):
    def __init__(self, message: str, status_code: int = 503) -> None:
        super().__init__(message)
        self.status_code = status_code


def make_sources(**overrides):
    state = {
        "writes": [],
        "posts": [],
        "review": {"final_review_status": "reviewer_advisory"},
    }

    def write(alert_id, payload):
        state["writes"].append((alert_id, payload))

    def post(path, payload):
        state["posts"].append((path, payload))
        return {"ok": True, "accepted": payload}

    values = {
        "now_iso": lambda: "2026-08-07T12:00:00Z",
        "validate_store_id": lambda value: (
            str(value) if str(value) == "index:alert-id" else ""
        ),
        "status_response": lambda: {"ok": True, "statuses": {}},
        "current_repeat_count": lambda alert_id: 7,
        "suppression_review_state": lambda alert_id: state["review"],
        "write_offline_status": write,
        "post_alert_store": post,
        "alert_store_error": StoreError,
        "alert_store_configured": True,
        "direct_write_allowed": False,
    }
    values.update(overrides)
    return SocAlertStatusWriteSources(**values), state


class SocAlertStatusWriteTest(unittest.TestCase):
    def test_legacy_bulk_state_is_read_only(self) -> None:
        sources, state = make_sources()
        ok, payload = update_soc_alert_status(
            sources, {"statuses": {"abcdef123456": {"status": "suppressed"}}}
        )
        self.assertTrue(ok)
        self.assertTrue(payload["ok"])
        self.assertEqual(state["writes"], [])
        self.assertEqual(state["posts"], [])

    def test_invalid_id_and_status_are_rejected(self) -> None:
        sources, _ = make_sources()
        self.assertFalse(update_soc_alert_status(sources, {"id": "bad/id"})[0])
        ok, payload = update_soc_alert_status(
            sources, {"id": "abcdef123456", "status": "deleted"}
        )
        self.assertFalse(ok)
        self.assertEqual(payload["error"], "Invalid SOC alert status")

    def test_production_posts_normalized_request_to_alert_store(self) -> None:
        sources, state = make_sources()
        ok, payload = update_soc_alert_status(
            sources,
            {
                "id": "index:alert-id",
                "acknowledged": True,
                "reason": " x " * 100,
            },
        )
        self.assertTrue(ok)
        self.assertTrue(payload["ok"])
        path, request = state["posts"][0]
        self.assertEqual(path, "/analyst-status")
        self.assertEqual(request["status"], "acknowledged")
        self.assertEqual(request["repeat_count"], 7)
        self.assertEqual(request["updated_by"], "dashboard")
        self.assertLessEqual(len(request["reason"]), 140)
        self.assertEqual(state["writes"], [])

    def test_alert_store_error_preserves_http_status(self) -> None:
        def fail(path, payload):
            raise StoreError("busy", 429)

        sources, _ = make_sources(post_alert_store=fail)
        ok, payload = update_soc_alert_status(
            sources, {"id": "abcdef123456", "status": "open"}
        )
        self.assertFalse(ok)
        self.assertEqual(payload["status"], 429)
        self.assertIn("busy", payload["error"])

    def test_direct_write_requires_offline_dr_opt_in(self) -> None:
        sources, state = make_sources(alert_store_configured=False)
        ok, payload = update_soc_alert_status(
            sources, {"id": "abcdef123456", "status": "acknowledged"}
        )
        self.assertFalse(ok)
        self.assertEqual(payload["status"], 503)
        self.assertEqual(state["writes"], [])

    def test_offline_dr_writes_then_returns_current_state(self) -> None:
        sources, state = make_sources(
            alert_store_configured=False,
            direct_write_allowed=True,
        )
        ok, payload = update_soc_alert_status(
            sources,
            {"id": "abcdef123456", "status": "acknowledged", "repeat_count": "3"},
        )
        self.assertTrue(ok)
        self.assertTrue(payload["ok"])
        self.assertEqual(state["writes"][0][1]["repeat_count"], 3)
        self.assertEqual(state["posts"], [])

    def test_offline_suppression_blocks_unresolved_review(self) -> None:
        sources, state = make_sources(
            alert_store_configured=False,
            direct_write_allowed=True,
        )
        state["review"] = {"final_review_status": "disputed_pending_human"}
        ok, payload = update_soc_alert_status(
            sources, {"id": "abcdef123456", "status": "suppressed"}
        )
        self.assertFalse(ok)
        self.assertEqual(payload["status"], 409)
        self.assertEqual(state["writes"], [])


if __name__ == "__main__":
    unittest.main()
