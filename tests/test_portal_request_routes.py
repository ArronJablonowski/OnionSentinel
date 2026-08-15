import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_request_routes as routes  # noqa: E402


CTI = "/api/cyber-threat-intel/program"
PROMPTS = frozenset({"/api/soc-settings/analyst-prompt"})


class PortalRequestRouteTests(unittest.TestCase):
    def classify(self, path: str) -> routes.PostRoute:
        return routes.classify_post_route(
            path, cti_program_path=CTI, prompt_paths=PROMPTS
        )

    def classify_get(self, path: str) -> routes.GetRoute:
        return routes.classify_get_route(
            path, cti_program_path=CTI, prompt_paths=PROMPTS
        )

    def test_exact_get_routes_have_stable_operations(self) -> None:
        for path, operation in routes.GET_EXACT_OPERATIONS.items():
            with self.subTest(path=path):
                route = self.classify_get(path)
                self.assertEqual(route.operation, operation)
                self.assertIsNone(route.resource_id)

    def test_runtime_get_routes_are_explicit(self) -> None:
        self.assertEqual(self.classify_get(CTI).operation, "cti_program")
        self.assertEqual(
            self.classify_get(next(iter(PROMPTS))).operation,
            "soc_settings_prompt",
        )

    def test_dynamic_get_routes_decode_their_resource_once(self) -> None:
        cases = (
            ("/api/soc-incidents/ir%20one/adjudications", "incident_adjudications", "ir one"),
            ("/api/soc-incidents/ir%20one/detail", "incident_detail", "ir one"),
            ("/api/soc-alerts/group%20one/adjudications", "alert_adjudications", "group one"),
            ("/api/soc-alerts/group%20one/detail", "alert_detail_fragment", "group one"),
            ("/api/soc-alerts/alert%20one", "alert_detail", "alert one"),
        )
        for path, operation, resource_id in cases:
            with self.subTest(path=path):
                route = self.classify_get(path)
                self.assertEqual(route.operation, operation)
                self.assertEqual(route.resource_id, resource_id)

    def test_unknown_get_route_is_left_for_catalog_routing(self) -> None:
        route = self.classify_get("/view/report-id/asset.png")
        self.assertIsNone(route.operation)
        self.assertIsNone(route.resource_id)

    def test_exact_form_and_json_routes_are_acceptlisted(self) -> None:
        paths = (
            "/admin/login", "/admin/logout", "/admin/action",
            "/api/admin/start-service", "/api/ac-hunter/refresh",
            "/api/soc-alerts/status",
            "/api/soc-settings/ai-model", "/api/soc-settings/agent-model",
            "/api/resource-library/remove", "/api/resource-library/tags",
            "/api/resource-library/rename", "/api/resource-library/favorite",
            "/api/assets/promote-dhcp", "/api/assets/approve-dhcp-ip-change",
            "/api/assets/update", "/api/assets/demote", CTI,
            next(iter(PROMPTS)),
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(self.classify(path).accepted)

    def test_dynamic_soc_write_routes_preserve_existing_contract(self) -> None:
        paths = (
            ("/api/soc-alerts/group/ack", "soc_alert_ack", "group"),
            ("/api/soc-alerts/group/pcap", "soc_alert_pcap", "group"),
            ("/api/soc-alerts/group/analyze", "soc_alert_analyze", "group"),
            ("/api/soc-alerts/group/escalate", "soc_alert_escalate", "group"),
            ("/api/soc-alerts/group/adjudicate", "soc_alert_adjudicate", "group"),
            ("/api/soc-incidents/ir-case/adjudicate", "soc_incident_adjudicate", "ir-case"),
            ("/api/soc-incidents/ir-case/status", "soc_incident_status", "ir-case"),
            ("/api/soc-incidents/ir-case/reanalyze", "soc_incident_reanalyze", "ir-case"),
            ("/api/soc-incidents/reanalyze-all", "soc_incident_reanalyze_all", None),
        )
        for path, operation, resource_id in paths:
            with self.subTest(path=path):
                route = self.classify(path)
                self.assertTrue(route.accepted)
                self.assertTrue(route.json_request)
                self.assertEqual(route.operation, operation)
                self.assertEqual(route.resource_id, resource_id)

    def test_dynamic_resource_ids_are_decoded_once_by_route_policy(self) -> None:
        route = self.classify("/api/soc-alerts/group%20one%2Fchild/analyze")
        self.assertEqual(route.operation, "soc_alert_analyze")
        self.assertEqual(route.resource_id, "group one/child")

    def test_route_roles_are_independent_and_cti_limit_is_explicit(self) -> None:
        cti = self.classify(CTI)
        asset = self.classify("/api/assets/update")
        review = self.classify("/api/soc-incidents/ir-case/adjudicate")
        reanalysis = self.classify("/api/soc-incidents/ir-case/reanalyze")
        self.assertTrue(cti.cti_program_write)
        self.assertTrue(asset.asset_write)
        self.assertTrue(review.review_write)
        self.assertTrue(reanalysis.incident_reanalysis)
        self.assertEqual(cti.request_limit(123_456), 123_456)
        self.assertEqual(asset.request_limit(123_456), 50_000)

    def test_unknown_or_read_only_post_routes_are_rejected(self) -> None:
        for path in (
            "/", "/api/reports", "/api/soc-alerts", "/api/soc-incidents",
            "/api/unknown", "/api/resource-library/unknown",
        ):
            with self.subTest(path=path):
                route = self.classify(path)
                self.assertFalse(route.accepted)
                self.assertFalse(route.json_request)

    def test_head_allowlist_and_content_types_match_legacy_handler(self) -> None:
        allowed = (
            "/", "/index.html", "/admin", "/admin/login",
            "/api/soc-alerts", "/api/soc-alerts/events", CTI,
            next(iter(PROMPTS)), "/api/soc-incidents/ir-case/detail",
            "/api/soc-alerts/group/detail", "/api/soc-alerts/group/analyze",
        )
        for path in allowed:
            with self.subTest(path=path):
                self.assertTrue(routes.is_head_route(
                    path, cti_program_path=CTI, prompt_paths=PROMPTS
                ))
        for path in (
            "/api/unknown", "/api/soc-alerts/group/ack",
            "/api/soc-alerts/group/escalate",
        ):
            with self.subTest(path=path):
                self.assertFalse(routes.is_head_route(
                    path, cti_program_path=CTI, prompt_paths=PROMPTS
                ))
        self.assertEqual(routes.head_content_type("/"), "text/html; charset=utf-8")
        self.assertEqual(
            routes.head_content_type("/api/soc-alerts/events"),
            "text/event-stream; charset=utf-8",
        )
        self.assertEqual(
            routes.head_content_type("/api/soc-alerts"),
            "application/json; charset=utf-8",
        )


if __name__ == "__main__":
    unittest.main()
