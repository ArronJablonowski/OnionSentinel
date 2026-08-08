#!/usr/bin/env python3
"""Direct contracts for Administration service-start request policy."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_service_write import (  # noqa: E402
    AdminServiceWriteCallbacks,
    prepare_admin_service_write,
)
from portal_request_routes import classify_post_route  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cyber-threat-intel/program",
        prompt_paths=frozenset(),
    )


def callbacks(**overrides) -> AdminServiceWriteCallbacks:
    values = {
        "expected_token": lambda: "token-1",
        "start_service": lambda service: (
            True, f"Started {service}.", {"id": service},
        ),
    }
    values.update(overrides)
    return AdminServiceWriteCallbacks(**values)


class AdminServiceWriteTests(unittest.TestCase):
    def test_other_route_is_declined_without_auth_or_token_access(self) -> None:
        calls: list[str] = []
        result = prepare_admin_service_write(
            route("/api/soc-alerts/status"), "{}",
            admin_authenticated=lambda: calls.append("auth") or True,
            callbacks=callbacks(
                expected_token=lambda: calls.append("token") or "token-1",
            ),
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_authentication_precedes_token_and_dispatch(self) -> None:
        calls: list[str] = []
        result = prepare_admin_service_write(
            route("/api/admin/start-service"),
            '{"token":"token-1","service":"codex"}',
            admin_authenticated=lambda: False,
            callbacks=callbacks(
                expected_token=lambda: calls.append("token") or "token-1",
                start_service=lambda _service: self.fail("must not start"),
            ),
        )
        self.assertEqual(result.status, 403)
        self.assertEqual(calls, [])
        self.assertIn("Sign in", result.payload["error"])

    def test_token_mismatch_prevents_dispatch(self) -> None:
        result = prepare_admin_service_write(
            route("/api/admin/start-service"),
            '{"token":"wrong","service":"codex"}',
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                start_service=lambda _service: self.fail("must not start"),
            ),
        )
        self.assertEqual(result.status, 403)
        self.assertIn("token validation failed", result.payload["error"])

    def test_success_strips_service_id_and_projects_status(self) -> None:
        received: list[str] = []
        result = prepare_admin_service_write(
            route("/api/admin/start-service"),
            '{"token":"token-1","service":" codex "}',
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                start_service=lambda service: (
                    received.append(service) or True,
                    "Started.",
                    {"id": service, "running": False},
                ),
            ),
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(received, ["codex"])
        self.assertEqual(result.payload["service"]["id"], "codex")

    def test_start_failure_maps_message_to_error_and_bad_request(self) -> None:
        result = prepare_admin_service_write(
            route("/api/admin/start-service"),
            '{"token":"token-1","service":"unknown"}',
            admin_authenticated=lambda: True,
            callbacks=callbacks(
                start_service=lambda _service: (False, "Unknown service.", None),
            ),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(result.payload["message"], "Unknown service.")
        self.assertEqual(result.payload["error"], "Unknown service.")


if __name__ == "__main__":
    unittest.main()
