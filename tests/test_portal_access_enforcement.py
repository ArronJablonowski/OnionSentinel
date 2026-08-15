from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_access_enforcement as enforcement  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402
from portal_session_principal import HumanPrincipal  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths={"/api/soc-settings/analyst-prompt"},
    )


def principal(role: str = "administrator") -> HumanPrincipal:
    return HumanPrincipal("human_session", "operator-1", role)


class PortalAccessEnforcementTests(unittest.TestCase):
    def decide(
        self,
        path: str,
        *,
        mode: str,
        actor: HumanPrincipal | None = None,
        origin: bool = True,
        csrf: bool = True,
    ) -> enforcement.AccessDecision:
        return enforcement.decide_write_access(
            route(path),
            mode=mode,
            principal=actor,
            same_origin_authorized=origin,
            csrf_authorized=csrf,
        )

    def test_mode_parser_is_explicit_and_unknown_values_fail_closed(self) -> None:
        for mode in (
            "legacy",
            "observe",
            "admin-enforce",
            "rbac-enforce",
        ):
            self.assertEqual(enforcement.parse_mode(mode), mode)
        for value in ("", "LEGACY", "true", "off", "unknown", None):
            with self.subTest(value=value):
                with self.assertRaises(enforcement.AccessEnforcementError):
                    enforcement.parse_mode(value)

    def test_legacy_and_observe_preserve_response_while_reporting_denial(self) -> None:
        for mode in ("legacy", "observe"):
            with self.subTest(mode=mode):
                decision = self.decide(
                    "/api/soc-settings/ai-model",
                    mode=mode,
                    actor=None,
                    origin=False,
                    csrf=False,
                )
                self.assertTrue(decision.allowed)
                self.assertFalse(decision.enforced)
                self.assertFalse(decision.would_authorize)
                self.assertEqual(decision.permission, "settings.manage")
                self.assertEqual(decision.reason, "unauthenticated")

    def test_admin_enforcement_gates_administrative_writes_only(self) -> None:
        settings = self.decide(
            "/api/soc-settings/ai-model",
            mode="admin-enforce",
            actor=principal("analyst"),
        )
        self.assertFalse(settings.allowed)
        self.assertTrue(settings.enforced)
        self.assertEqual(settings.reason, "role_denied")

        analyst_route = self.decide(
            "/api/soc-alerts/group/escalate",
            mode="admin-enforce",
            actor=None,
            origin=False,
            csrf=False,
        )
        self.assertTrue(analyst_route.allowed)
        self.assertFalse(analyst_route.enforced)
        self.assertFalse(analyst_route.would_authorize)

    def test_rbac_enforcement_applies_exact_role_permissions(self) -> None:
        cases = (
            ("viewer", "/api/soc-alerts/group/escalate", False),
            ("analyst", "/api/soc-alerts/group/escalate", True),
            ("analyst", "/api/soc-settings/ai-model", False),
            ("administrator", "/api/soc-settings/ai-model", True),
        )
        for role, path, expected in cases:
            with self.subTest(role=role, path=path):
                decision = self.decide(
                    path,
                    mode="rbac-enforce",
                    actor=principal(role),
                )
                self.assertIs(decision.allowed, expected)
                self.assertTrue(decision.enforced)
                self.assertIs(decision.would_authorize, expected)

    def test_denial_order_is_principal_role_origin_then_csrf(self) -> None:
        cases = (
            (None, False, False, "unauthenticated"),
            (principal("viewer"), False, False, "role_denied"),
            (principal("administrator"), False, False, "origin_denied"),
            (principal("administrator"), True, False, "csrf_denied"),
            (principal("administrator"), True, True, "authorized"),
        )
        for actor, origin, csrf, reason in cases:
            with self.subTest(reason=reason):
                decision = self.decide(
                    "/api/soc-settings/ai-model",
                    mode="rbac-enforce",
                    actor=actor,
                    origin=origin,
                    csrf=csrf,
                )
                self.assertEqual(decision.reason, reason)

    def test_service_principal_and_unknown_kind_are_never_human_authorized(self) -> None:
        service = HumanPrincipal("service_identity", "service-1", "administrator")
        decision = self.decide(
            "/api/soc-settings/ai-model",
            mode="rbac-enforce",
            actor=service,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "role_denied")

    def test_login_remains_a_separate_credential_authentication_boundary(self) -> None:
        for mode in enforcement.ACCESS_MODES:
            decision = self.decide("/admin/login", mode=mode)
            self.assertTrue(decision.allowed)
            self.assertFalse(decision.enforced)
            self.assertTrue(decision.would_authorize)
            self.assertIsNone(decision.permission)
            self.assertEqual(decision.reason, "authentication_boundary")


if __name__ == "__main__":
    unittest.main()
