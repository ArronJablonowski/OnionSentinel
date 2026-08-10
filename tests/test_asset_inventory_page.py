#!/usr/bin/env python3
"""Contracts for authoritative asset identity APIs and dashboard rendering."""
from __future__ import annotations

import datetime as dt
import io
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
PORTAL_PATH = DASHBOARD_DIR / "report_portal.py"
ASSET_WRITE_POLICY_PATH = DASHBOARD_DIR / "portal_asset_write_request.py"
JSON_WRITE_SERVICE_PATH = DASHBOARD_DIR / "portal_json_write_service.py"
HTTP_HANDLER_PATH = DASHBOARD_DIR / "portal_http_handler.py"
BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
ASSET_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_asset_inventory_page.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AssetWriteRequest:
    """Minimal request stub for exercising asset-write authorization."""

    def __init__(
        self,
        path: str,
        payload: dict,
        *,
        same_origin: bool = True,
        authenticated: bool = False,
    ):
        body = json.dumps(payload).encode("utf-8")
        self.path = path
        self.headers = {"Content-Length": str(len(body))}
        self.rfile = io.BytesIO(body)
        self.same_origin = same_origin
        self.authenticated = authenticated
        self.admin_auth_checks = 0
        self.response: tuple[int, dict] | None = None

    def _soc_review_write_authorized(self) -> bool:
        return self.same_origin

    def _admin_authenticated(self) -> bool:
        self.admin_auth_checks += 1
        return self.authenticated

    def _send(self, status: int, body: bytes, _content_type: str = "") -> None:
        self.response = (int(status), json.loads(body.decode("utf-8")))


class AssetInventoryPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.inventory_path = Path(self.tmp.name) / "asset_inventory.json"
        self.dhcp_state_path = (
            Path(self.tmp.name) / "dhcp-observations.json"
        )
        self.portal = load_module("asset_inventory_page_portal", PORTAL_PATH)
        self.portal.ASSET_INVENTORY_FILE = self.inventory_path
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = self.dhcp_state_path
        self.portal.ASSET_INVENTORY_CACHE = {
            "signature": None,
            "inventory": None,
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def asset(
        asset_id: str,
        ip: str,
        hostname: str,
        valid_from: str,
        valid_until: str | None = None,
    ) -> dict:
        return {
            "asset_id": asset_id,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "identifiers": {
                "ip_addresses": [ip],
                "hostnames": [hostname] if hostname else [],
            },
            "role": "workstation",
            "platform": "macOS",
            "owner_ref": "must-not-be-exposed",
            "criticality": "medium",
            "expected_services": [],
            "expected_behaviors": ["operator-only context"],
            "source_type": "operator-verified",
            "source_ref": "inventory-ticket",
            "confidence": "high",
            "share_with_hosted_models": False,
        }

    def write_inventory(self, assets: list[dict]) -> None:
        self.inventory_path.write_text(
            json.dumps(
                {
                    "schema": "onion-sentinel-asset-inventory-v1",
                    "version": 1,
                    "generated_at": "2026-07-29T12:00:00-06:00",
                    "assets": assets,
                }
            ),
            encoding="utf-8",
        )

    def test_api_returns_only_current_sanitized_assignments(self) -> None:
        self.write_inventory(
            [
                self.asset(
                    "current-mac",
                    "10.66.6.210",
                    "current-mac.example.lan",
                    "2026-07-01T00:00:00-06:00",
                ),
                self.asset(
                    "retired-mac",
                    "10.66.6.211",
                    "retired-mac.example.lan",
                    "2025-01-01T00:00:00-07:00",
                    "2026-01-01T00:00:00-07:00",
                ),
            ]
        )

        status, payload = self.portal.asset_inventory_response(
            observed_at=dt.datetime(
                2026,
                7,
                29,
                18,
                0,
                tzinfo=dt.timezone.utc,
            )
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["records_total"], 2)
        self.assertEqual(payload["current_asset_count"], 1)
        self.assertEqual(payload["state_counts"]["expired"], 1)
        self.assertEqual(payload["assets"][0]["asset_id"], "current-mac")
        self.assertEqual(payload["assets"][0]["ip_addresses"], ["10.66.6.210"])
        self.assertEqual(
            payload["assets"][0]["hostnames"],
            ["current-mac.example.lan"],
        )
        self.assertNotIn("owner_ref", payload["assets"][0])
        self.assertNotIn("expected_behaviors", payload["assets"][0])

    def test_api_overlays_moved_known_asset_and_adds_provisional_client(
        self,
    ) -> None:
        self.write_inventory(
            [
                self.asset(
                    "current-mac",
                    "10.66.6.210",
                    "current-mac.example.lan",
                    "2026-07-01T00:00:00-06:00",
                )
            ]
        )
        self.dhcp_state_path.write_text(
            json.dumps(
                {
                    "schema": "onion-sentinel-dhcp-asset-observations-v1",
                    "version": 1,
                    "updated_at": "2026-07-29T17:30:00Z",
                    "collection": {
                        "status": "ok",
                        "last_success_at": "2026-07-29T17:30:00Z",
                    },
                    "observations": [
                        {
                            "discovery_id": "known",
                            "current_ip": "10.66.6.220",
                            "mac_address": "",
                            "hostname": "current-mac.example.lan",
                            "first_seen": "2026-07-29T17:00:00Z",
                            "last_seen": "2026-07-29T17:30:00Z",
                            "lease_expires_at": "2026-07-29T18:30:00Z",
                        },
                        {
                            "discovery_id": "candidate",
                            "current_ip": "10.66.6.230",
                            "mac_address": "aa:bb:cc:dd:ee:ff",
                            "hostname": "new-client.example.lan",
                            "first_seen": "2026-07-29T17:05:00Z",
                            "last_seen": "2026-07-29T17:25:00Z",
                            "lease_expires_at": "2026-07-29T18:25:00Z",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.asset_inventory_response(
            observed_at=dt.datetime(
                2026,
                7,
                29,
                18,
                0,
                tzinfo=dt.timezone.utc,
            )
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["authoritative_asset_count"], 1)
        self.assertEqual(payload["discovered_asset_count"], 1)
        self.assertEqual(payload["current_asset_count"], 2)
        by_id = {item["asset_id"]: item for item in payload["assets"]}
        known = by_id["current-mac"]
        self.assertEqual(known["ip_addresses"], ["10.66.6.220"])
        self.assertEqual(
            known["configured_ip_addresses"],
            ["10.66.6.210"],
        )
        self.assertEqual(known["current_ip_source"], "zeek-dhcp")
        candidate = by_id["dhcp-candidate"]
        self.assertEqual(candidate["state"], "observed")
        self.assertEqual(candidate["ip_addresses"], ["10.66.6.230"])
        self.assertEqual(
            candidate["source_type"],
            "zeek-dhcp-observation",
        )
        self.assertEqual(
            candidate["mac_address_scope"],
            "locally_administered",
        )

    def test_ip_resolution_uses_event_time_and_refuses_ambiguity(self) -> None:
        old = self.asset(
            "old-owner",
            "10.66.6.210",
            "old-owner.example.lan",
            "2025-01-01T00:00:00-07:00",
            "2026-07-01T00:00:00-06:00",
        )
        current = self.asset(
            "current-owner",
            "10.66.6.210",
            "current-owner.example.lan",
            "2026-07-01T00:00:00-06:00",
        )
        self.write_inventory([old, current])
        inventory, error = self.portal.load_asset_inventory_data()
        self.assertEqual(error, "")

        historical = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-06-15  12:00:00-06:00",
            inventory,
        )
        present = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-07-29  12:00:00-06:00",
            inventory,
        )

        self.assertEqual(historical["hostname"], "old-owner.example.lan")
        self.assertEqual(present["hostname"], "current-owner.example.lan")

        conflict = self.asset(
            "conflicting-owner",
            "10.66.6.210",
            "conflict.example.lan",
            "2026-07-01T00:00:00-06:00",
        )
        self.write_inventory([current, conflict])
        self.portal.ASSET_INVENTORY_CACHE = {
            "signature": None,
            "inventory": None,
        }
        inventory, error = self.portal.load_asset_inventory_data()
        self.assertEqual(error, "")
        ambiguous = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-07-29  12:00:00-06:00",
            inventory,
        )
        self.assertEqual(ambiguous["status"], "ambiguous")
        self.assertNotIn("hostname", ambiguous)

    def test_database_api_labels_exact_ip_dhcp_mac_as_observed(self) -> None:
        inventory_payload = {
            "ok": True,
            "assets": [
                {
                    "asset_id": "current-mac",
                    "state": "current",
                    "ip_addresses": ["10.66.6.210"],
                    "mac_addresses": [],
                    "hostnames": ["current-mac.example.lan"],
                }
            ],
        }
        dhcp_state = {
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "updated_at": "2026-07-30T20:00:00Z",
            "collection": {"status": "ok"},
            "observations": [
                {
                    "current_ip": "10.66.6.210",
                    "mac_address": "14:75:5b:3f:90:17",
                    "last_seen": "2026-07-30T20:00:00Z",
                    "lease_expires_at": "2099-07-30T21:00:00Z",
                }
            ],
        }

        def store_response(path: str, timeout: float = 5.0) -> dict:
            if path.startswith("/assets/inventory?"):
                return inventory_payload
            if path == "/assets/dhcp-state":
                return {"state": dhcp_state}
            raise AssertionError(path)

        with (
            mock.patch.object(
                self.portal,
                "ASSET_DATABASE_READ_ENABLED",
                True,
            ),
            mock.patch.object(
                self.portal,
                "alert_store_get_json",
                side_effect=store_response,
            ),
        ):
            status, payload = self.portal.asset_inventory_response()

        self.assertEqual(status, 200)
        record = payload["assets"][0]
        self.assertEqual(record["mac_addresses"], [])
        self.assertEqual(
            record["observed_mac_addresses"],
            ["14:75:5b:3f:90:17"],
        )
        self.assertEqual(
            record["observed_mac_source"],
            "zeek-dhcp-exact-ip",
        )
        self.assertFalse(record["observed_mac_stale"])
        self.assertEqual(payload["dhcp_discovery"]["status"], "ok")

    def test_asset_page_and_navigation_are_generated(self) -> None:
        builder = load_module("asset_inventory_page_builder", BUILDER_PATH)
        builder.DB_PATH = Path(self.tmp.name) / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = Path(self.tmp.name) / "pcap-artifacts"

        page = builder.render_static_page(
            builder.build_html([]),
            "asset_inventory",
            [],
        )
        incident_page = builder.render_static_page(
            builder.build_html([]),
            "investigations",
            [],
        )

        builder_source = BUILDER_PATH.read_text(encoding="utf-8")
        asset_page_source = ASSET_PAGE_PATH.read_text(encoding="utf-8")
        installer_source = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "from dashboard_asset_inventory_page import asset_inventory_page_section",
            builder_source,
        )
        self.assertIn("def asset_inventory_page_section()", asset_page_source)
        copy_command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_asset_inventory_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_asset_inventory_page.py"'
        )
        self.assertEqual(installer_source.count(copy_command), 1)

        self.assertIn('<h1 id="page-title">Asset Inventory</h1>', page)
        self.assertIn('id="asset-inventory-view"', page)
        self.assertIn("fetch('/api/asset-inventory'", page)
        self.assertIn("Current IP address", page)
        self.assertIn(
            "<th>Asset</th><th>State</th><th>Current IP address</th>"
            "<th>MAC address</th><th>Hostname</th>",
            page,
        )
        self.assertIn(
            '<td><strong class="asset-name" title="${esc(item.asset_id)}">'
            '${esc(item.asset_id)}</strong></td>'
            '<td><span class="asset-state">${esc(item.state||\'current\')}</span></td>',
            page,
        )
        self.assertIn("<th>From</th><th>Until</th><th>Source</th>", page)
        self.assertIn(
            '<td class="asset-validity">${timestamp(item.valid_from)}</td>'
            '<td class="asset-validity">${timestamp(item.valid_until)}',
            page,
        )
        self.assertNotIn("<th>Validity</th>", page)
        self.assertIn('colspan="12" class="ir-loading">Loading known assets', page)
        self.assertIn(".asset-table th:nth-child(11){width:190px}", page)
        self.assertIn(".asset-table th:nth-child(1){width:220px}", page)
        self.assertIn(".asset-table th:nth-child(4){width:155px}", page)
        self.assertIn(".asset-table th:nth-child(5){width:220px}", page)
        self.assertIn("const macValues=item=>", page)
        self.assertIn("item.observed_mac_addresses", page)
        self.assertIn("Observed via DHCP", page)
        self.assertIn("review required", page)
        self.assertIn(".asset-mac{white-space:nowrap!important", page)
        self.assertIn("text-overflow:ellipsis;white-space:nowrap!important", page)
        self.assertIn('title="${esc(value)}">${esc(value)}</code>', page)
        self.assertIn("text-overflow:ellipsis;white-space:nowrap", page)
        self.assertIn("Current address from passive DHCP", page)
        self.assertIn("provisional DHCP observation", page)
        self.assertIn("Historical backfill has not run", page)
        self.assertIn("mac_address_scope", page)
        self.assertIn("<th>Evidence</th><th>Action</th>", page)
        self.assertIn('data-dhcp-promote="${esc(item.discovery_id)}"', page)
        self.assertIn('data-dhcp-ip-change="${esc(item.discovery_id)}"', page)
        self.assertIn('id="dhcp-review-modal"', page)
        self.assertIn(
            'id="dhcp-review-form" class="dhcp-review-card" novalidate',
            page,
        )
        self.assertIn("X-Onion-Sentinel-Request':'dashboard'", page)
        self.assertIn("PROMOTE:${item.discovery_id}", page)
        self.assertIn("CHANGE-IP:${item.discovery_id}:${authority.asset_id}", page)
        self.assertIn("fetch('/api/admin/session-status'", page)
        self.assertIn("adminRequired=false", page)
        self.assertIn("payload.required===true", page)
        self.assertIn("if(adminRequired&&adminAuthenticated!==true)", page)
        self.assertIn(
            "Administration sign-in is not required.",
            page,
        )
        self.assertIn("resumeAfterAuth=true", page)
        self.assertIn("this change will resume automatically", page)
        self.assertIn("closeReview();pageOffset=0", page)
        self.assertNotIn("search.value=promotedAssetId", page)
        self.assertIn('class="asset-promoted"', page)
        self.assertIn('data-asset-edit="${esc(item.asset_id)}"', page)
        self.assertIn('data-asset-demote="${esc(item.asset_id)}"', page)
        self.assertIn('id="asset-review-modal"', page)
        self.assertIn("'/api/assets/update'", page)
        self.assertIn("'/api/assets/demote'", page)
        self.assertIn("demoting?'DEMOTE':'EDIT'", page)
        self.assertIn("assetReviewMode==='demote'?'DEMOTE':'EDIT'", page)
        self.assertIn('data-discovery-id="${esc(item.discovery_id)}"', page)
        self.assertIn("returned to DHCP review", page)
        self.assertIn("when:assetCanRefresh", page)
        self.assertIn(".dhcp-review-check[hidden]{display:none!important}", page)
        self.assertIn("asset-inventory.html", page)
        portal_source = PORTAL_PATH.read_text(encoding="utf-8")
        handler_source = HTTP_HANDLER_PATH.read_text(encoding="utf-8")
        asset_write_policy = ASSET_WRITE_POLICY_PATH.read_text(encoding="utf-8")
        json_write_service = JSON_WRITE_SERVICE_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "ASSET_INVENTORY_ADMIN_WRITE_REQUIRED",
            portal_source,
        )
        self.assertIn('"authentication_required"', asset_write_policy)
        self.assertIn(
            "dispatch_json_write(",
            handler_source,
        )
        self.assertIn("prepare_asset_write_request(", json_write_service)
        self.assertIn(
            "Asset inventory changes must come from the same-origin Onion Sentinel dashboard.",
            asset_write_policy,
        )
        self.assertIn("const assetIdentityHtml=asset=>", incident_page)
        self.assertIn("item.source_asset", incident_page)
        self.assertIn("item.destination_asset", incident_page)

    def test_asset_promotion_does_not_require_login_by_default(self) -> None:
        request = AssetWriteRequest(
            "/api/assets/promote-dhcp",
            {"bounded": "payload"},
            authenticated=False,
        )
        with (
            mock.patch.object(
                self.portal,
                "ASSET_INVENTORY_ADMIN_WRITE_REQUIRED",
                False,
            ),
            mock.patch.object(
                self.portal,
                "asset_dhcp_promotion_response",
                return_value=(201, {"ok": True, "asset_id": "lan-client"}),
            ) as promote,
        ):
            self.portal.PortalHandler.do_POST(request)

        self.assertEqual(
            request.response,
            (201, {"ok": True, "asset_id": "lan-client"}),
        )
        self.assertEqual(request.admin_auth_checks, 0)
        promote.assert_called_once_with({"bounded": "payload"})

    def test_asset_promotion_still_requires_same_origin(self) -> None:
        request = AssetWriteRequest(
            "/api/assets/promote-dhcp",
            {"bounded": "payload"},
            same_origin=False,
        )
        with (
            mock.patch.object(
                self.portal,
                "ASSET_INVENTORY_ADMIN_WRITE_REQUIRED",
                False,
            ),
            mock.patch.object(
                self.portal,
                "asset_dhcp_promotion_response",
            ) as promote,
        ):
            self.portal.PortalHandler.do_POST(request)

        self.assertIsNotNone(request.response)
        status, body = request.response
        self.assertEqual(status, 403)
        self.assertIn("same-origin", body["error"])
        promote.assert_not_called()

    def test_asset_promotion_login_can_be_enabled_later(self) -> None:
        request = AssetWriteRequest(
            "/api/assets/promote-dhcp",
            {"bounded": "payload"},
            authenticated=False,
        )
        with (
            mock.patch.object(
                self.portal,
                "ASSET_INVENTORY_ADMIN_WRITE_REQUIRED",
                True,
            ),
            mock.patch.object(
                self.portal,
                "asset_dhcp_promotion_response",
            ) as promote,
        ):
            self.portal.PortalHandler.do_POST(request)

        self.assertIsNotNone(request.response)
        status, body = request.response
        self.assertEqual(status, 403)
        self.assertTrue(body["authentication_required"])
        self.assertEqual(request.admin_auth_checks, 1)
        promote.assert_not_called()

    def test_installer_deploys_shared_inventory_validator(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        launch_agent = (
            ROOT
            / "n8n"
            / "launchd"
            / "com.arron.onion-sentinel.web.plist"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/asset_inventory.py" '
            '"$DASHBOARD_RUNTIME_DIR/asset_inventory.py"',
            installer,
        )
        self.assertIn(
            "<key>ASSET_INVENTORY_ADMIN_WRITE_REQUIRED</key>",
            launch_agent,
        )
        self.assertIn("<string>false</string>", launch_agent)

    def test_dashboard_asset_review_payloads_are_bounded_and_exact(self) -> None:
        promotion = {
            "discovery_id": "0123456789abcdef0123",
            "expected_ip": "192.0.2.25",
            "expected_mac": "00-11-22-33-44-55",
            "expected_hostname": "Candidate.LAN.",
            "asset_id": "candidate",
            "hostname": "candidate.lan",
            "role": "workstation",
            "platform": "macOS",
            "criticality": "medium",
            "operator_ref": "change-123",
            "reason": "Reviewed DHCP evidence.",
            "confirm": "PROMOTE:0123456789abcdef0123",
            "accept_locally_administered_mac": False,
        }
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
            return_value={"ok": True, "status": "promoted"},
        ) as post:
            status, result = self.portal.asset_dhcp_promotion_response(
                promotion
            )
        self.assertEqual(status, 201)
        self.assertTrue(result["ok"])
        path, payload = post.call_args.args
        self.assertEqual(path, "/assets/promote-dhcp")
        self.assertEqual(payload["expected_mac"], "00:11:22:33:44:55")
        self.assertEqual(payload["expected_hostname"], "candidate.lan")

        invalid = dict(promotion)
        invalid["unexpected"] = "must fail closed"
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
        ) as blocked_post:
            status, result = self.portal.asset_dhcp_promotion_response(invalid)
        self.assertEqual(status, 400)
        self.assertFalse(result["ok"])
        blocked_post.assert_not_called()

    def test_ip_change_approval_uses_dedicated_internal_route(self) -> None:
        payload = {
            "discovery_id": "fedcba9876543210fedc",
            "expected_ip": "192.0.2.30",
            "expected_mac": "",
            "expected_hostname": "known.lan",
            "asset_id": "known",
            "operator_ref": "change-456",
            "reason": "Stable hostname verified.",
            "confirm": "CHANGE-IP:fedcba9876543210fedc:known",
        }
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
            return_value={"ok": True, "status": "ip_change_approved"},
        ) as post:
            status, result = self.portal.asset_dhcp_ip_change_response(payload)
        self.assertEqual(status, 201)
        self.assertEqual(result["status"], "ip_change_approved")
        self.assertEqual(
            post.call_args.args[0],
            "/assets/approve-dhcp-ip-change",
        )

    def test_asset_edit_and_demotion_use_bounded_internal_routes(self) -> None:
        common = {
            "asset_id": "known",
            "expected_valid_from": "2026-07-30T20:00:00Z",
            "operator_ref": "change-789",
            "reason": "Operator reviewed the authoritative record.",
        }
        edit = {
            **common,
            "confirm": "EDIT:known",
            "ip_addresses": ["192.0.2.40"],
            "mac_addresses": ["00-11-22-33-44-66"],
            "hostnames": ["Known.LAN."],
            "role": "workstation",
            "platform": "macOS",
            "criticality": "medium",
            "confidence": "high",
        }
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
            return_value={"ok": True, "status": "edited"},
        ) as post:
            status, result = self.portal.asset_update_response(edit)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        path, payload = post.call_args.args
        self.assertEqual(path, "/assets/update")
        self.assertEqual(payload["mac_addresses"], ["00:11:22:33:44:66"])
        self.assertEqual(payload["hostnames"], ["known.lan"])

        demote = {
            **common,
            "confirm": "DEMOTE:known",
        }
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
            return_value={
                "ok": True,
                "status": "demoted",
                "discovery_ids": ["0123456789abcdef0123"],
            },
        ) as post:
            status, result = self.portal.asset_demote_response(demote)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(post.call_args.args[0], "/assets/demote")

        invalid = dict(edit)
        invalid["unexpected"] = "blocked"
        with mock.patch.object(
            self.portal,
            "asset_store_post_json",
        ) as blocked_post:
            status, result = self.portal.asset_update_response(invalid)
        self.assertEqual(status, 400)
        self.assertFalse(result["ok"])
        blocked_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
