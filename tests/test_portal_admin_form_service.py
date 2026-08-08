#!/usr/bin/env python3
"""Direct contracts for Administration form orchestration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_form_service import (  # noqa: E402
    AdminFormCallbacks,
    prepare_admin_form,
)
from portal_request_routes import classify_post_route  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=frozenset(),
    )


def callbacks(**overrides) -> AdminFormCallbacks:
    values = {
        "expected_token": lambda: "token-1",
        "password_configured": lambda: True,
        "verify_password": lambda password: password == "correct",
        "create_session": lambda _client_ip: "session-1",
        "session_cookie": lambda session: f"session={session}",
        "current_session_id": lambda: "session-1",
        "destroy_session": lambda _session: None,
        "expired_session_cookie": lambda: "session=; Max-Age=0",
        "start_action": lambda _action, _confirmation: (True, "Started update."),
    }
    values.update(overrides)
    return AdminFormCallbacks(**values)


class AdminFormServiceTests(unittest.TestCase):
    def invoke(self, path: str, raw: str, **kwargs):
        return prepare_admin_form(
            route(path), raw,
            client_ip="192.0.2.10",
            admin_authenticated=kwargs.pop("admin_authenticated", lambda: False),
            callbacks=callbacks(**kwargs),
        )

    def test_non_form_route_is_declined_without_token_access(self) -> None:
        calls: list[str] = []
        result = prepare_admin_form(
            route("/api/soc-alerts/status"), "token=token-1",
            client_ip="192.0.2.10",
            admin_authenticated=lambda: calls.append("auth") or True,
            callbacks=callbacks(
                expected_token=lambda: calls.append("token") or "token-1",
            ),
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_token_failure_uses_dashboard_only_for_authenticated_action(self) -> None:
        authenticated = self.invoke(
            "/admin/action", "token=wrong",
            admin_authenticated=lambda: True,
        )
        login = self.invoke("/admin/login", "token=wrong")
        self.assertEqual((authenticated.status, authenticated.view), (403, "dashboard"))
        self.assertEqual((login.status, login.view), (403, "login"))

    def test_login_reports_unconfigured_and_invalid_password(self) -> None:
        unavailable = self.invoke(
            "/admin/login", "token=token-1&password=correct",
            password_configured=lambda: False,
        )
        invalid = self.invoke(
            "/admin/login", "token=token-1&password=wrong",
        )
        self.assertEqual(unavailable.status, 503)
        self.assertIn("not configured", unavailable.message)
        self.assertEqual(invalid.status, 401)
        self.assertIn("Invalid", invalid.message)

    def test_successful_login_binds_client_session_cookie_and_redirect(self) -> None:
        clients: list[str] = []
        result = self.invoke(
            "/admin/login", "token=token-1&password=correct",
            create_session=lambda client: clients.append(client) or "new-session",
        )
        self.assertEqual(result.status, 302)
        self.assertEqual(result.redirect, "/admin")
        self.assertEqual(result.headers["Set-Cookie"], "session=new-session")
        self.assertEqual(clients, ["192.0.2.10"])

    def test_logout_destroys_current_session_and_expires_cookie(self) -> None:
        destroyed: list[str] = []
        result = self.invoke(
            "/admin/logout", "token=token-1",
            destroy_session=destroyed.append,
        )
        self.assertEqual(destroyed, ["session-1"])
        self.assertEqual(result.redirect, "/admin/login")
        self.assertIn("Max-Age=0", result.headers["Set-Cookie"])

    def test_action_requires_session_after_valid_token(self) -> None:
        result = self.invoke("/admin/action", "token=token-1&action=update")
        self.assertEqual(result.status, 403)
        self.assertEqual(result.view, "login")
        self.assertIn("Sign in", result.message)

    def test_action_redirect_encodes_success_and_failure_messages(self) -> None:
        success = self.invoke(
            "/admin/action", "token=token-1&action=update&confirmation=YES",
            admin_authenticated=lambda: True,
            start_action=lambda action, confirmation: (
                action == "update" and confirmation == "YES", "Started update."
            ),
        )
        failure = self.invoke(
            "/admin/action", "token=token-1&action=bad",
            admin_authenticated=lambda: True,
            start_action=lambda _action, _confirmation: (False, "Unknown action."),
        )
        self.assertEqual(success.status, 303)
        self.assertEqual(success.redirect, "/admin?admin_msg=Started%20update.")
        self.assertEqual(failure.redirect, "/admin?admin_error=Unknown%20action.")


if __name__ == "__main__":
    unittest.main()
