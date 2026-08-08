#!/usr/bin/env python3
"""Direct contracts for Asset mutation and write-request policy."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_asset_mutation_service import (  # noqa: E402
    execute_asset_mutation,
    normalize_asset_mutation_payload,
    normalize_asset_review_payload,
)
from portal_asset_write_request import prepare_asset_write_request  # noqa: E402
from portal_request_routes import classify_post_route  # noqa: E402


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def asset_route(path: str):
    return classify_post_route(
        path,
        cti_program_path="/api/cti",
        prompt_paths=frozenset(),
    )


def promotion_payload() -> dict:
    return {
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


def edit_payload() -> dict:
    return {
        "asset_id": "known",
        "expected_valid_from": "2026-07-30T20:00:00-06:00",
        "operator_ref": "change-789",
        "reason": "Operator reviewed the authoritative record.",
        "confirm": "EDIT:known",
        "ip_addresses": ["192.0.2.40", "192.0.2.40"],
        "mac_addresses": ["00-11-22-33-44-66"],
        "hostnames": ["Known.LAN."],
        "role": "workstation",
        "platform": "macOS",
        "criticality": "medium",
        "confidence": "high",
    }


class AssetMutationPolicyTests(unittest.TestCase):
    def test_promotion_normalizes_evidence_without_expanding_fields(self) -> None:
        normalized = normalize_asset_review_payload(
            promotion_payload(), action="promote",
        )
        self.assertEqual(normalized["expected_ip"], "192.0.2.25")
        self.assertEqual(normalized["expected_mac"], "00:11:22:33:44:55")
        self.assertEqual(normalized["expected_hostname"], "candidate.lan")
        self.assertFalse(normalized["accept_locally_administered_mac"])

    def test_review_rejects_unknown_and_invalid_evidence(self) -> None:
        unknown = {**promotion_payload(), "unbounded": "blocked"}
        with self.assertRaisesRegex(ValueError, "unsupported asset review"):
            normalize_asset_review_payload(unknown, action="promote")
        invalid = {**promotion_payload(), "expected_ip": "not-an-address"}
        with self.assertRaisesRegex(ValueError, "expected_ip is invalid"):
            normalize_asset_review_payload(invalid, action="promote")

    def test_edit_normalizes_identifiers_timestamp_and_duplicates(self) -> None:
        normalized = normalize_asset_mutation_payload(
            edit_payload(), action="edit", parse_timestamp=parse_timestamp,
        )
        self.assertEqual(normalized["expected_valid_from"], "2026-07-31T02:00:00Z")
        self.assertEqual(normalized["ip_addresses"], ["192.0.2.40"])
        self.assertEqual(normalized["mac_addresses"], ["00:11:22:33:44:66"])
        self.assertEqual(normalized["hostnames"], ["known.lan"])

    def test_edit_requires_exact_confirmation_and_usable_identifier(self) -> None:
        wrong = {**edit_payload(), "confirm": "EDIT:other"}
        with self.assertRaisesRegex(ValueError, "exactly match EDIT:known"):
            normalize_asset_mutation_payload(
                wrong, action="edit", parse_timestamp=parse_timestamp,
            )
        multicast = {**edit_payload(), "mac_addresses": ["01:00:5e:00:00:01"]}
        with self.assertRaisesRegex(ValueError, "multicast MAC"):
            normalize_asset_mutation_payload(
                multicast, action="edit", parse_timestamp=parse_timestamp,
            )

    def test_execute_clears_cache_only_after_success(self) -> None:
        cleared: list[bool] = []
        status, result = execute_asset_mutation(
            {"value": 1},
            normalizer=lambda payload: dict(payload),
            path="/assets/update",
            success_status=200,
            write=lambda _path, payload: {"ok": True, **payload},
            clear_cache=lambda: cleared.append(True),
        )
        self.assertEqual((status, result["value"], cleared), (200, 1, [True]))

        class Conflict(RuntimeError):
            status_code = 409

        status, result = execute_asset_mutation(
            {},
            normalizer=lambda payload: dict(payload),
            path="/assets/update",
            success_status=200,
            write=lambda _path, _payload: (_ for _ in ()).throw(Conflict("conflict")),
            clear_cache=lambda: cleared.append(False),
        )
        self.assertEqual(status, 409)
        self.assertEqual(result["error"], "conflict")
        self.assertEqual(cleared, [True])


class AssetWriteRequestPolicyTests(unittest.TestCase):
    def test_same_origin_failure_precedes_optional_admin_check(self) -> None:
        auth_calls: list[bool] = []
        dispatched: list[object] = []
        result = prepare_asset_write_request(
            asset_route("/api/assets/update"),
            "{}",
            same_origin_authorized=False,
            admin_required=True,
            admin_authenticated=lambda: auth_calls.append(True) or False,
            dispatcher=lambda path, payload: dispatched.append((path, payload)) or (200, {}),
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.status, 403)
        self.assertEqual(auth_calls, [])
        self.assertEqual(dispatched, [])

    def test_admin_policy_is_lazy_and_explicit(self) -> None:
        auth_calls: list[bool] = []
        result = prepare_asset_write_request(
            asset_route("/api/assets/update"),
            "{}",
            same_origin_authorized=True,
            admin_required=True,
            admin_authenticated=lambda: auth_calls.append(True) or False,
            dispatcher=lambda _path, _payload: (200, {}),
        )
        self.assertEqual(result.status, 403)
        self.assertTrue(result.payload["authentication_required"])
        self.assertEqual(auth_calls, [True])

    def test_malformed_json_reaches_bounded_endpoint_validator_as_none(self) -> None:
        dispatched: list[tuple[str, object]] = []
        result = prepare_asset_write_request(
            asset_route("/api/assets/demote"),
            "{not-json",
            same_origin_authorized=True,
            admin_required=False,
            admin_authenticated=lambda: self.fail("admin check must be skipped"),
            dispatcher=lambda path, payload: dispatched.append((path, payload)) or (
                400, {"ok": False, "error": "Request body must be a JSON object."},
            ),
        )
        self.assertEqual(result.status, 400)
        self.assertEqual(dispatched, [("/api/assets/demote", None)])


if __name__ == "__main__":
    unittest.main()
