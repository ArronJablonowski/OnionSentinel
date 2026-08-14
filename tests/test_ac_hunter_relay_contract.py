#!/usr/bin/env python3
"""Security and routing contracts for the restricted AC Hunter relay."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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


def load_broker():
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_broker_characterization",
        BROKER_PATH,
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
        cls.broker = load_broker()

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

    def relay_response(self, **overrides: object) -> dict[str, object]:
        response: dict[str, object] = {
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
        response.update(overrides)
        return response

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

    def test_login_encoding_optional_order_and_request_shape_are_exact(self) -> None:
        cases = (
            (
                {
                    "email": "service@example.invalid",
                    "password": "opaque value",
                    "csrf_token": "csrf/value",
                    "next": "/jwt/json",
                    "remember": True,
                },
                b"email=service%40example.invalid&password=opaque+value&next=%2Fjwt%2Fjson&submit=Login&csrf_token=csrf%2Fvalue&remember=y",
            ),
            (
                {
                    "email": "service@example.invalid",
                    "password": "opaque value",
                },
                b"email=service%40example.invalid&password=opaque+value&next=&submit=Login",
            ),
        )
        for body, expected in cases:
            with self.subTest(body=body):
                _request_id, request = self.contract.compile_request(
                    self.envelope(
                        "login",
                        headers={"cookie": "session=synthetic"},
                        body=body,
                    )
                )
                self.assertEqual(
                    request,
                    self.contract.UpstreamRequest(
                        method="POST",
                        path="/auth/login",
                        headers={
                            "Accept": "text/html, application/xhtml+xml;q=0.9",
                            "User-Agent": "Onion-Sentinel-AC-Hunter/1.0",
                            "Cookie": "session=synthetic",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        body=expected,
                        response_kind="none",
                        allowed_statuses=(302, 303),
                    ),
                )

    def test_login_validation_errors_and_precedence_are_exact(self) -> None:
        base = {
            "email": "service@example.invalid",
            "password": "opaque",
        }
        cases = (
            ({**base, "extra": True}, "body contains unsupported fields: extra"),
            ({**base, "email": "invalid"}, "email is invalid"),
            ({**base, "password": ""}, "password is empty or exceeds its byte limit"),
            ({**base, "next": "/admin"}, "next is outside the AC Hunter auth flow"),
            ({**base, "remember": 1}, "remember must be boolean"),
            (
                {"email": "invalid", "password": "", "remember": 1},
                "email is invalid",
            ),
        )
        for body, expected in cases:
            with self.subTest(body=body):
                with self.assertRaises(self.contract.AcHunterContractError) as caught:
                    self.contract.compile_request(self.envelope("login", body=body))
                self.assertEqual(str(caught.exception), expected)

    def test_relay_response_is_bound_to_request_and_has_bounded_shape(
        self,
    ) -> None:
        payload = self.relay_response()
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

    def test_relay_response_validation_errors_and_precedence_are_exact(self) -> None:
        cases = (
            ({"extra": True}, "relay response contains unsupported fields: extra"),
            ({"request_id": "b" * 32}, "relay response binding is invalid"),
            ({"ok": 1}, "relay response ok must be boolean"),
            ({"status": True}, "relay response status is invalid"),
            ({"status": 600}, "relay response status is invalid"),
            ({"duration_ms": False}, "relay response duration is invalid"),
            ({"duration_ms": 300001}, "relay response duration is invalid"),
            ({"headers": []}, "relay response headers must be an object"),
            (
                {"headers": {"location": "", "set_cookie": [], "extra": 1}},
                "relay response headers contains unsupported fields: extra",
            ),
            (
                {"headers": {"location": "bad\nvalue", "set_cookie": []}},
                "relay response location contains a forbidden control character",
            ),
            (
                {"headers": {"location": "", "set_cookie": ["x"] * 9}},
                "relay response cookie list is invalid",
            ),
            (
                {"headers": {"location": "", "set_cookie": [""]}},
                "relay response cookie is empty or exceeds its byte limit",
            ),
            ({"error": "bad\rvalue"}, "relay response error contains a forbidden control character"),
            (
                {"content_type": "x" * 257},
                "relay response content type is empty or exceeds its byte limit",
            ),
            (
                {"ok": 1, "status": 600, "duration_ms": 300001},
                "relay response ok must be boolean",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                payload = self.relay_response(**overrides)
                with self.assertRaises(self.contract.AcHunterContractError) as caught:
                    self.contract.validate_relay_response(payload, "a" * 32)
                self.assertEqual(str(caught.exception), expected)

    def test_contract_namespace_and_public_signatures_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.contract) if not name.startswith("__")
        )
        encoded = json.dumps(
            names,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (46, "39d83b34d47fdfb7ac7b803a78d1e18e2d80ac4da24ccf22fc606847b238a7bf"),
        )
        signatures = {
            name: str(inspect.signature(getattr(self.contract, name)))
            for name in ("compile_request", "validate_relay_response")
        }
        self.assertEqual(
            signatures,
            {
                "compile_request": "(payload: 'object') -> 'tuple[str, UpstreamRequest]'",
                "validate_relay_response": "(payload: 'object', request_id: 'str') -> 'dict[str, Any]'",
            },
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

    def test_broker_config_admission_preserves_exact_defaults_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "ac-hunter.json"
            ca_bundle = Path(directory) / "ca.pem"
            value = {
                "schema": self.broker.CONFIG_SCHEMA,
                "enabled": True,
                "upstream_ip": "192.168.1.12",
                "upstream_port": 443,
                "tls_server_name": "localhost",
                "ca_bundle": str(ca_bundle),
                "certificate_sha256": "a" * 64,
            }
            config_path.write_text(json.dumps(value), encoding="utf-8")
            config_stat = config_path.stat()
            calls = []

            def secure(path, *, maximum_bytes, owner_uid=0):
                calls.append((path, maximum_bytes, owner_uid))
                return config_stat

            with mock.patch.object(
                self.broker,
                "_secure_regular_file",
                side_effect=secure,
            ):
                loaded = self.broker._load_config(config_path)

        self.assertEqual(loaded["ca_bundle"], ca_bundle)
        self.assertEqual(loaded["lock_file"], self.broker.DEFAULT_LOCK)
        self.assertNotIn("connect_timeout_seconds", loaded)
        self.assertNotIn("request_timeout_seconds", loaded)
        self.assertNotIn("max_response_bytes", loaded)
        self.assertEqual(
            calls,
            [
                (config_path, self.broker.MAX_CONFIG_BYTES, 0),
                (ca_bundle, 128 * 1024, 0),
            ],
        )

    def test_broker_config_rejects_limits_only_after_ca_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "ac-hunter.json"
            ca_bundle = Path(directory) / "ca.pem"
            value = {
                "schema": self.broker.CONFIG_SCHEMA,
                "enabled": True,
                "upstream_ip": "192.168.1.12",
                "upstream_port": 443,
                "tls_server_name": "localhost",
                "ca_bundle": str(ca_bundle),
                "certificate_sha256": "a" * 64,
                "connect_timeout_seconds": True,
            }
            config_path.write_text(json.dumps(value), encoding="utf-8")
            config_stat = config_path.stat()
            calls = []

            def secure(path, *, maximum_bytes, owner_uid=0):
                calls.append(path)
                return config_stat

            with mock.patch.object(
                self.broker,
                "_secure_regular_file",
                side_effect=secure,
            ):
                with self.assertRaisesRegex(
                    self.broker.BrokerError,
                    "connect timeout is invalid",
                ):
                    self.broker._load_config(config_path)

        self.assertEqual(calls, [config_path, ca_bundle])

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
