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

    def test_exact_form_and_json_routes_are_acceptlisted(self) -> None:
        paths = (
            "/admin/login", "/admin/logout", "/admin/action",
            "/api/admin/start-service", "/api/soc-alerts/status",
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
            "/api/soc-alerts/group/ack", "/api/soc-alerts/group/pcap",
            "/api/soc-alerts/group/analyze", "/api/soc-alerts/group/escalate",
            "/api/soc-alerts/group/adjudicate",
            "/api/soc-incidents/ir-case/adjudicate",
            "/api/soc-incidents/ir-case/status",
            "/api/soc-incidents/ir-case/reanalyze",
            "/api/soc-incidents/reanalyze-all",
        )
        for path in paths:
            with self.subTest(path=path):
                route = self.classify(path)
                self.assertTrue(route.accepted)
                self.assertTrue(route.json_request)

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
