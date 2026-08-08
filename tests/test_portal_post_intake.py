#!/usr/bin/env python3
"""Contracts for portal POST intake policy."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_post_intake import prepare_post_intake  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cti-program",
        prompt_paths={"/api/soc-settings/analyst-prompt"},
    )


class PostIntakeTests(unittest.TestCase):
    def prepare(self, path: str, length: str | None, authenticated=False):
        calls: list[str] = []
        result = prepare_post_intake(
            route(path), length, cti_file_bytes=120_000,
            admin_authenticated=lambda: calls.append("auth") or authenticated,
        )
        return result, calls

    def test_unknown_route_is_not_found_without_authentication(self) -> None:
        result, calls = self.prepare("/unknown", "10")
        self.assertEqual(result.status, 404)
        self.assertEqual(result.body, b"Not found")
        self.assertEqual(calls, [])

    def test_valid_request_is_ready_and_preserves_length(self) -> None:
        result, calls = self.prepare("/api/soc-alerts/status", "123")
        self.assertTrue(result.ready)
        self.assertEqual(result.length, 123)
        self.assertEqual(calls, [])

    def test_missing_invalid_and_nonpositive_json_lengths_share_error(self) -> None:
        for value in (None, "invalid", "0", "-1", "50001"):
            with self.subTest(value=value):
                result, calls = self.prepare("/api/soc-alerts/status", value)
                self.assertEqual(result.status, 400)
                self.assertEqual(
                    result.body,
                    b'{"ok": false, "error": "Invalid request size"}',
                )
                self.assertEqual(result.content_type, "application/json; charset=utf-8")
                self.assertEqual(calls, [])

    def test_cti_route_uses_its_larger_file_limit(self) -> None:
        accepted, _ = self.prepare("/api/cti-program", "120000")
        rejected, _ = self.prepare("/api/cti-program", "120001")
        self.assertTrue(accepted.ready)
        self.assertEqual(rejected.status, 400)

    def test_invalid_login_form_selects_login_without_authentication(self) -> None:
        result, calls = self.prepare("/admin/login", "0")
        self.assertEqual(result.view, "login")
        self.assertEqual(result.message, "Invalid request size.")
        self.assertEqual(calls, [])

    def test_invalid_admin_action_selects_dashboard_only_when_authenticated(self) -> None:
        dashboard, dashboard_calls = self.prepare("/admin/action", "0", True)
        login, login_calls = self.prepare("/admin/action", "0", False)
        self.assertEqual(dashboard.view, "dashboard")
        self.assertEqual(dashboard.message, "Invalid admin action request size.")
        self.assertEqual(login.view, "login")
        self.assertEqual(dashboard_calls, ["auth"])
        self.assertEqual(login_calls, ["auth"])


if __name__ == "__main__":
    unittest.main()
