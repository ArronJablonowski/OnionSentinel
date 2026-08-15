from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_access_policy as policy  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402


CTI = "/api/cyber-threat-intel/program"
PROMPTS = frozenset({"/api/soc-settings/analyst-prompt"})


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path=CTI,
        prompt_paths=PROMPTS,
    )


class PortalAccessPolicyTests(unittest.TestCase):
    def test_installer_deploys_access_session_and_audit_modules(self) -> None:
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        for name in (
            "portal_access_policy.py",
            "portal_access_enforcement.py",
            "portal_session_principal.py",
            "portal_admin_audit_chain.py",
            "portal_admin_audit_store.py",
            "portal_access_observer.py",
            "portal_access_observer_runtime.py",
        ):
            with self.subTest(name=name):
                self.assertIn(
                    f'cp "$REPO_DIR/onion-sentinel-dashboard/{name}" '
                    f'"$DASHBOARD_RUNTIME_DIR/{name}"',
                    installer,
                )

    def test_human_roles_are_explicit_and_monotonically_privileged(self) -> None:
        self.assertEqual(
            policy.HUMAN_ROLES,
            frozenset({"viewer", "analyst", "administrator"}),
        )
        viewer = policy.ROLE_PERMISSIONS["viewer"]
        analyst = policy.ROLE_PERMISSIONS["analyst"]
        administrator = policy.ROLE_PERMISSIONS["administrator"]
        self.assertLess(viewer, analyst)
        self.assertLess(analyst, administrator)
        self.assertEqual(viewer, frozenset({"evidence.view", "session.logout"}))

    def test_service_identities_can_never_satisfy_human_permissions(self) -> None:
        for role in policy.HUMAN_ROLES:
            for permission in policy.ROLE_PERMISSIONS[role]:
                with self.subTest(role=role, permission=permission):
                    self.assertFalse(
                        policy.is_authorized(
                            principal_kind="service_identity",
                            role=role,
                            permission=permission,
                        )
                    )
        self.assertFalse(
            policy.is_authorized(
                principal_kind="human_session",
                role="service",
                permission="evidence.view",
            )
        )

    def test_role_permissions_cover_required_operator_capabilities(self) -> None:
        analyst = policy.ROLE_PERMISSIONS["analyst"]
        administrator = policy.ROLE_PERMISSIONS["administrator"]
        self.assertTrue(
            {
                "alert.acknowledge",
                "alert.escalate",
                "alert.adjudicate",
                "incident.adjudicate",
                "incident.status",
                "case.reanalyze",
                "evidence.capture-request",
            }.issubset(analyst)
        )
        self.assertTrue(
            {
                "asset.manage",
                "cti.manage",
                "settings.manage",
                "integration.manage",
                "resource.manage",
                "privileged-action.execute",
            }.issubset(administrator)
        )

    def test_every_classified_write_has_one_permission_or_auth_boundary(self) -> None:
        cases = {
            "/admin/login": None,
            "/admin/logout": "session.logout",
            "/admin/action": "privileged-action.execute",
            "/api/admin/start-service": "integration.manage",
            "/api/ac-hunter/refresh": "integration.manage",
            "/api/soc-alerts/status": "incident.status",
            "/api/soc-settings/ai-model": "settings.manage",
            "/api/soc-settings/agent-model": "settings.manage",
            next(iter(PROMPTS)): "settings.manage",
            "/api/resource-library/remove": "resource.manage",
            "/api/resource-library/tags": "resource.manage",
            "/api/resource-library/rename": "resource.manage",
            "/api/resource-library/favorite": "resource.manage",
            "/api/assets/promote-dhcp": "asset.manage",
            "/api/assets/approve-dhcp-ip-change": "asset.manage",
            "/api/assets/update": "asset.manage",
            "/api/assets/demote": "asset.manage",
            CTI: "cti.manage",
            "/api/soc-alerts/group/ack": "alert.acknowledge",
            "/api/soc-alerts/group/pcap": "evidence.capture-request",
            "/api/soc-alerts/group/analyze": "case.reanalyze",
            "/api/soc-alerts/group/escalate": "alert.escalate",
            "/api/soc-alerts/group/adjudicate": "alert.adjudicate",
            "/api/soc-incidents/ir/adjudicate": "incident.adjudicate",
            "/api/soc-incidents/ir/status": "incident.status",
            "/api/soc-incidents/ir/reanalyze": "case.reanalyze",
            "/api/soc-incidents/reanalyze-all": "case.reanalyze",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                classified = route(path)
                self.assertTrue(classified.accepted)
                self.assertEqual(policy.required_permission(classified), expected)

    def test_unknown_and_rejected_routes_fail_closed(self) -> None:
        with self.assertRaisesRegex(policy.AccessPolicyError, "not an accepted write"):
            policy.required_permission(route("/api/unknown"))
        self.assertFalse(
            policy.is_authorized(
                principal_kind="human_session",
                role="administrator",
                permission="unknown.permission",
            )
        )

    def test_viewer_analyst_and_administrator_decisions_are_exact(self) -> None:
        self.assertTrue(policy.is_human_authorized("viewer", "evidence.view"))
        self.assertFalse(policy.is_human_authorized("viewer", "alert.escalate"))
        self.assertTrue(policy.is_human_authorized("analyst", "alert.escalate"))
        self.assertFalse(policy.is_human_authorized("analyst", "settings.manage"))
        self.assertTrue(
            policy.is_human_authorized("administrator", "settings.manage")
        )


if __name__ == "__main__":
    unittest.main()
