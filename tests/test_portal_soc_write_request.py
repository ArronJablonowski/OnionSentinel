"""Direct contracts for SOC write authorization and JSON request policy."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_request_routes import classify_post_route  # noqa: E402
from portal_soc_write_dispatch import SocWriteCallbacks  # noqa: E402
from portal_soc_write_request import prepare_soc_write_request  # noqa: E402


class SocWriteRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[tuple] = []
        callback = lambda resource, payload: (200, {"ok": True})
        self.callbacks = SocWriteCallbacks(
            alert_ack=callback,
            alert_pcap=callback,
            alert_analyze=callback,
            alert_escalate=callback,
            alert_adjudicate=callback,
            incident_adjudicate=callback,
            incident_status=callback,
            incident_reanalyze=callback,
            incident_reanalyze_all=lambda payload: (200, {"ok": True}),
        )

    @staticmethod
    def route(path):
        return classify_post_route(
            path,
            cti_program_path="/api/cyber-threat-intel/program",
            prompt_paths=frozenset(),
        )

    def prepare(self, path, raw, *, authorized=True, status=202):
        def dispatcher(route, payload, callbacks):
            self.calls.append((route.operation, payload, callbacks))
            return status, {"ok": status < 400}

        return prepare_soc_write_request(
            self.route(path),
            raw,
            same_origin_authorized=authorized,
            dispatcher=dispatcher,
            callbacks=self.callbacks,
        )

    def test_review_and_reanalysis_require_same_origin_before_dispatch(self) -> None:
        for path, message in (
            (
                "/api/soc-alerts/group/adjudicate",
                "Analyst review writes must come from the same-origin dashboard.",
            ),
            (
                "/api/soc-incidents/case/reanalyze",
                "Incident reanalysis requests must come from the same-origin dashboard.",
            ),
        ):
            with self.subTest(path=path):
                result = self.prepare(path, "{}", authorized=False)
                self.assertEqual(result.status, 403)
                self.assertEqual(result.payload["error"], message)
        self.assertEqual(self.calls, [])

    def test_strict_json_errors_remain_distinct(self) -> None:
        malformed_review = self.prepare(
            "/api/soc-alerts/group/adjudicate", "{bad"
        )
        malformed_reanalysis = self.prepare(
            "/api/soc-incidents/case/reanalyze", "{bad"
        )
        non_object_review = self.prepare(
            "/api/soc-alerts/group/adjudicate", "[]"
        )

        self.assertEqual(
            malformed_review.payload["error"], "Request body must be valid JSON."
        )
        self.assertEqual(
            malformed_reanalysis.payload["error"], "Request body must be a JSON object."
        )
        self.assertEqual(
            non_object_review.payload["error"], "Request body must be a JSON object."
        )
        self.assertEqual(self.calls, [])

    def test_alert_actions_preserve_lenient_malformed_json_fallback(self) -> None:
        result = self.prepare("/api/soc-alerts/group/ack", "{bad")

        self.assertEqual(result.status, 202)
        self.assertEqual(self.calls[0][1], {})
        self.assertTrue(result.clear_cache)

    def test_success_only_requests_cache_invalidation(self) -> None:
        accepted = self.prepare("/api/soc-alerts/group/analyze", "{}", status=202)
        rejected = self.prepare("/api/soc-alerts/group/analyze", "{}", status=400)

        self.assertTrue(accepted.clear_cache)
        self.assertFalse(rejected.clear_cache)

    def test_non_soc_route_is_declined(self) -> None:
        result = self.prepare("/api/assets/update", "{}")
        self.assertIsNone(result)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
