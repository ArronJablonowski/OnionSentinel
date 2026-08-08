#!/usr/bin/env python3
"""Direct contracts for legacy SOC alert-status request orchestration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_request_routes import classify_post_route  # noqa: E402
from portal_soc_status_write import prepare_soc_status_write  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=frozenset(),
    )


class SocStatusWriteTests(unittest.TestCase):
    def test_other_route_is_declined_without_update(self) -> None:
        result = prepare_soc_status_write(
            route("/api/admin/start-service"), "{}",
            update=lambda _payload: self.fail("must not update"),
        )
        self.assertIsNone(result)

    def test_success_preserves_payload_and_requests_cache_clear(self) -> None:
        received: list[dict] = []
        result = prepare_soc_status_write(
            route("/api/soc-alerts/status"),
            '{"id":"alert-1","status":"open"}',
            update=lambda payload: (
                received.append(payload) or True,
                {"ok": True, "status": "open"},
            ),
        )
        self.assertEqual(result.status, 200)
        self.assertTrue(result.clear_cache)
        self.assertEqual(received[0]["id"], "alert-1")

    def test_failure_preserves_explicit_downstream_status_without_cache_clear(self) -> None:
        result = prepare_soc_status_write(
            route("/api/soc-alerts/status"), "{}",
            update=lambda _payload: (
                False, {"ok": False, "error": "conflict", "status": 409},
            ),
        )
        self.assertEqual(result.status, 409)
        self.assertFalse(result.clear_cache)

    def test_failure_defaults_to_bad_request(self) -> None:
        result = prepare_soc_status_write(
            route("/api/soc-alerts/status"), "[]",
            update=lambda payload: (
                False, {"ok": False, "error": "invalid", "seen": payload},
            ),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(result.payload["seen"], {})


if __name__ == "__main__":
    unittest.main()
