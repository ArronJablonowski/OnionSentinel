#!/usr/bin/env python3
"""Security and routing contracts for the restricted AC Hunter relay."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "n8n" / "bin" / "ac_hunter_contract.py"
BROKER_PATH = ROOT / "relay" / "app" / "ac_hunter_broker.py"


def load_contract():
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_contract",
        CONTRACT_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AcHunterRelayContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()

    def envelope(
        self,
        operation: str,
        *,
        params: dict[str, object] | None = None,
        headers: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "contract": self.contract.CONTRACT,
            "request_id": "a" * 32,
            "operation": operation,
            "params": params or {},
            "headers": headers or {},
            "body": body or {},
        }

    def compiled_path(
        self,
        operation: str,
        *,
        params: dict[str, object] | None = None,
    ) -> str:
        _request_id, request = self.contract.compile_request(
            self.envelope(
                operation,
                params=params,
                headers={"authorization": "Bearer " + "x" * 32},
            )
        )
        return request.path

    def test_all_data_operations_compile_to_fixed_ac_hunter_paths(self) -> None:
        expected = {
            "database": "/api/v0/database",
            "dashboard": "/api/v0/security-onion-rolling/dashboard",
            "dashboard_count": (
                "/api/v0/security-onion-rolling/dashboard/count"
            ),
            "dashboard_c2flag": (
                "/api/v0/security-onion-rolling/dashboard/c2flag"
            ),
            "certificate_count": (
                "/api/v0/security-onion-rolling/certificate/count"
            ),
            "unexpected_ports": "/custom/unexpectedports.json",
        }
        for operation, path in expected.items():
            self.assertEqual(self.compiled_path(operation), path)

        self.assertEqual(
            self.compiled_path("beacons_count", params={"thresh": 0.5}),
            "/api/v0/security-onion-rolling/beacons/count?thresh=0.5",
        )
        for operation, suffix in (
            ("beacons", "beacons"),
            ("beacons_sni", "beaconssni"),
            ("beacons_proxy", "beaconsproxy"),
        ):
            self.assertEqual(
                self.compiled_path(
                    operation,
                    params={
                        "page": 1,
                        "size": 100,
                        "thresh": 0.5,
                        "sort": "score",
                    },
                ),
                (
                    f"/api/v0/security-onion-rolling/{suffix}"
                    "?page=1&size=100&thresh=0.5&sort=score"
                ),
            )
        self.assertEqual(
            self.compiled_path(
                "long_connections",
                params={
                    "page": 1,
                    "size": 100,
                    "min_length": 18000,
                    "sort": "duration",
                },
            ),
            (
                "/api/v0/security-onion-rolling/longconns"
                "?page=1&size=100&min-length=18000&sort=duration"
            ),
        )
        self.assertEqual(
            self.compiled_path(
                "dns",
                params={"page": 1, "size": 100, "threshold": 100},
            ),
            (
                "/api/v0/security-onion-rolling/dns"
                "?page=1&size=100&threshold=100"
            ),
        )
        self.assertEqual(
            self.compiled_path(
                "strobe",
                params={
                    "page": 1,
                    "size": 100,
                    "sort": "connection_count",
                },
            ),
            (
                "/api/v0/security-onion-rolling/strobe"
                "?page=1&size=100&sort=connection_count"
            ),
        )
        self.assertEqual(
            self.compiled_path(
                "blacklist_ip",
                params={"page": 1, "size": 100},
            ),
            (
                "/api/v0/security-onion-rolling/blacklist/ip"
                "?page=1&size=100"
            ),
        )
        self.assertEqual(
            self.compiled_path(
                "useragent_count",
                params={"ja3flag": True},
            ),
            "/api/v0/security-onion-rolling/useragent/count/true",
        )

    def test_caller_cannot_supply_url_host_path_method_or_tls_controls(
        self,
    ) -> None:
        forbidden_fields = (
            ("url", "https://attacker.invalid"),
            ("host", "attacker.invalid"),
            ("path", "/admin"),
            ("method", "DELETE"),
            ("proxy", "http://attacker.invalid"),
            ("verify_tls", False),
        )
        for field, value in forbidden_fields:
            payload = self.envelope("database")
            payload[field] = value
            with self.assertRaises(self.contract.AcHunterContractError):
                self.contract.compile_request(payload)

            payload = self.envelope("database", params={field: value})
            with self.assertRaises(self.contract.AcHunterContractError):
                self.contract.compile_request(payload)

    def test_only_bounded_cookie_and_bearer_headers_are_admitted(self) -> None:
        for headers in (
            {"authorization": "Basic abc"},
            {"authorization": "Bearer short"},
            {"authorization": "Bearer " + "x" * 32 + "\nInjected: yes"},
            {"cookie": "session=ok\r\nInjected: yes"},
            {"x-forwarded-host": "attacker.invalid"},
        ):
            with self.assertRaises(self.contract.AcHunterContractError):
                self.contract.compile_request(
                    self.envelope("database", headers=headers)
                )

    def test_login_contract_accepts_only_expected_form_fields(self) -> None:
        request_id, request = self.contract.compile_request(
            self.envelope(
                "login",
                headers={"cookie": "session=preauth"},
                body={
                    "email": "service@example.invalid",
                    "password": "opaque value",
                    "csrf_token": "csrf",
                    "next": "/jwt/json",
                    "remember": False,
                },
            )
        )
        self.assertEqual(request_id, "a" * 32)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/auth/login")
        self.assertNotIn("opaque value", request.path)
        self.assertIn(b"password=opaque+value", request.body)
        self.assertEqual(request.allowed_statuses, (302, 303))

        with self.assertRaises(self.contract.AcHunterContractError):
            self.contract.compile_request(
                self.envelope(
                    "login",
                    body={
                        "email": "service@example.invalid",
                        "password": "secret",
                        "csrf_token": "",
                        "next": "https://attacker.invalid",
                        "remember": False,
                    },
                )
            )

    def test_relay_response_is_bound_to_request_and_has_bounded_shape(
        self,
    ) -> None:
        payload = {
            "contract": self.contract.CONTRACT,
            "request_id": "a" * 32,
            "ok": True,
            "status": 200,
            "content_type": "application/json",
            "headers": {"location": "", "set_cookie": []},
            "body": {"data": []},
            "duration_ms": 15,
            "error": "",
        }
        self.assertIs(
            self.contract.validate_relay_response(payload, "a" * 32),
            payload,
        )
        mismatched = dict(payload, request_id="b" * 32)
        with self.assertRaises(self.contract.AcHunterContractError):
            self.contract.validate_relay_response(
                mismatched,
                "a" * 32,
            )

    def test_broker_source_has_one_fixed_upstream_and_no_request_logging(
        self,
    ) -> None:
        source = BROKER_PATH.read_text(encoding="utf-8")
        self.assertIn('value.get("upstream_ip") != "192.168.1.12"', source)
        self.assertIn('value.get("upstream_port") != 443', source)
        self.assertIn('value.get("tls_server_name") != "localhost"', source)
        self.assertNotIn("urllib.request", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("logging.", source)
        self.assertNotIn("print(", source)

    def test_contract_and_broker_compile_under_current_python(self) -> None:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "py_compile",
                str(CONTRACT_PATH),
                str(BROKER_PATH),
            ],
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
