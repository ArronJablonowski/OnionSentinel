#!/usr/bin/env python3
"""Application orchestration contracts for portal JSON writes."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

import portal_json_write_service as service  # noqa: E402
from portal_json_write_service import JsonWriteCallbacks  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402


def route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cti-program",
        prompt_paths={"/api/soc-settings/analyst-prompt"},
    )


class Result:
    def __init__(self, status=200, payload=None, clear_cache=False):
        self.status = status
        self.payload = payload or {"ok": True}
        self.clear_cache = clear_cache


class JsonWriteServiceTests(unittest.TestCase):
    def callbacks(self):
        return JsonWriteCallbacks(
            same_origin_authorized=Mock(return_value=True),
            cti_admin_authenticated=Mock(return_value=True),
            cti_program=object(),
            asset_admin_authenticated=Mock(return_value=True),
            asset_dispatcher=Mock(),
            soc_dispatcher=Mock(),
            soc=object(),
            clear_soc_cache=Mock(),
            status_update=Mock(),
            settings_admin_authenticated=Mock(return_value=True),
            settings=object(),
            admin_authenticated=Mock(return_value=True),
            admin_service=object(),
            resource_library=object(),
        )

    def test_cti_short_circuits_and_projects_result(self) -> None:
        callbacks = self.callbacks()
        with patch.object(service, "prepare_cti_program_write", return_value=Result(409, {"ok": False})) as prepare:
            result = service.dispatch_json_write(
                route("/api/cti-program"), "{}",
                asset_admin_required=True, callbacks=callbacks,
            )
        self.assertEqual((result.status, result.payload), (409, {"ok": False}))
        prepare.assert_called_once()
        callbacks.same_origin_authorized.assert_called_once()

    def test_asset_short_circuits_with_explicit_admin_policy(self) -> None:
        callbacks = self.callbacks()
        with patch.object(service, "prepare_asset_write_request", return_value=Result()) as prepare:
            result = service.dispatch_json_write(
                route("/api/assets/update"), "{}",
                asset_admin_required=True, callbacks=callbacks,
            )
        self.assertEqual(result.status, 200)
        self.assertTrue(prepare.call_args.kwargs["admin_required"])
        callbacks.same_origin_authorized.assert_called_once()

    def test_soc_success_invalidates_cache_once(self) -> None:
        callbacks = self.callbacks()
        with patch.object(service, "prepare_soc_write_request", return_value=Result(clear_cache=True)):
            result = service.dispatch_json_write(
                route("/api/soc-alerts/alert-1/analyze"), "{}",
                asset_admin_required=False, callbacks=callbacks,
            )
        self.assertEqual(result.status, 200)
        callbacks.clear_soc_cache.assert_called_once_with()
        callbacks.same_origin_authorized.assert_not_called()

    def test_review_write_checks_same_origin_and_does_not_clear_failed_result(self) -> None:
        callbacks = self.callbacks()
        with patch.object(service, "prepare_soc_write_request", return_value=Result(403)) as prepare:
            service.dispatch_json_write(
                route("/api/soc-alerts/alert-1/adjudicate"), "{}",
                asset_admin_required=False, callbacks=callbacks,
            )
        self.assertTrue(prepare.call_args.kwargs["same_origin_authorized"])
        callbacks.same_origin_authorized.assert_called_once()
        callbacks.clear_soc_cache.assert_not_called()

    def test_status_success_invalidates_cache(self) -> None:
        callbacks = self.callbacks()
        with patch.object(service, "prepare_soc_write_request", return_value=None), patch.object(
            service, "prepare_soc_status_write", return_value=Result(clear_cache=True),
        ):
            service.dispatch_json_write(
                route("/api/soc-alerts/status"), "{}",
                asset_admin_required=False, callbacks=callbacks,
            )
        callbacks.clear_soc_cache.assert_called_once_with()

    def test_form_route_is_declined_without_authorization_or_cache_effects(self) -> None:
        callbacks = self.callbacks()
        result = service.dispatch_json_write(
            route("/admin/login"), "username=a",
            asset_admin_required=False, callbacks=callbacks,
        )
        self.assertIsNone(result)
        callbacks.same_origin_authorized.assert_not_called()
        callbacks.cti_admin_authenticated.assert_not_called()
        callbacks.asset_admin_authenticated.assert_not_called()
        callbacks.settings_admin_authenticated.assert_not_called()
        callbacks.admin_authenticated.assert_not_called()
        callbacks.clear_soc_cache.assert_not_called()


if __name__ == "__main__":
    unittest.main()
