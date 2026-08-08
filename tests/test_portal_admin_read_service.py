#!/usr/bin/env python3
"""Direct contracts for Administration read orchestration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_read_service import prepare_admin_read  # noqa: E402


class AdminReadServiceTests(unittest.TestCase):
    def invoke(self, operation, *, authenticated=False, query=None, service=None):
        return prepare_admin_read(
            operation,
            query or {},
            admin_authenticated=lambda: authenticated,
            asset_write_auth_required=True,
            service_status=service or (lambda: {"ok": True, "services": {}}),
        )

    def test_non_admin_operation_is_declined_without_auth_or_probe(self) -> None:
        calls: list[str] = []
        result = prepare_admin_read(
            "health", {},
            admin_authenticated=lambda: calls.append("auth") or True,
            asset_write_auth_required=True,
            service_status=lambda: calls.append("probe") or {},
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_login_redirects_authenticated_session_or_renders_form(self) -> None:
        self.assertEqual(
            self.invoke("admin_login", authenticated=True).redirect, "/admin",
        )
        login = self.invoke("admin_login")
        self.assertEqual((login.status, login.view), (200, "login"))

    def test_dashboard_requires_auth_and_preserves_message_priority(self) -> None:
        denied = self.invoke("admin")
        shown = self.invoke(
            "admin", authenticated=True,
            query={"admin_msg": ["Saved"], "admin_error": ["Old error"]},
        )
        error = self.invoke(
            "admin", authenticated=True, query={"admin_error": ["Failed"]},
        )
        self.assertEqual(denied.redirect, "/admin/login")
        self.assertEqual((shown.message, shown.error), ("Saved", True))
        self.assertEqual((error.message, error.error), ("Failed", True))

    def test_session_status_is_public_and_projects_policy(self) -> None:
        result = self.invoke("admin_session_status", authenticated=False)
        self.assertEqual(result.status, 200)
        self.assertFalse(result.payload["authenticated"])
        self.assertTrue(result.payload["required"])

    def test_service_status_is_authenticated_and_probe_is_lazy(self) -> None:
        probes: list[str] = []
        denied = self.invoke(
            "admin_service_status",
            service=lambda: probes.append("probe") or {"ok": True},
        )
        allowed = self.invoke(
            "admin_service_status", authenticated=True,
            service=lambda: probes.append("probe") or {"ok": True},
        )
        self.assertEqual(denied.status, 403)
        self.assertEqual(probes, ["probe"])
        self.assertEqual(allowed.payload, {"ok": True})


if __name__ == "__main__":
    unittest.main()
