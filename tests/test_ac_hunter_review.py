#!/usr/bin/env python3
"""Focused tests for the Relay-only AC Hunter Deep Review backend."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "onion-sentinel-dashboard" / "ac_hunter_review.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "ac_hunter_review_test_module", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)


def jwt(expiry: float) -> str:
    def encoded(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encoded({'alg': 'HS256', 'typ': 'JWT'})}.{encoded({'exp': expiry})}.signature"


class AcHunterReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.key = self.root / "relay-key"
        self.known_hosts = self.root / "known-hosts"
        self.credentials = self.root / "credentials.json"
        self.cache = self.root / "cache" / "deep-review.json"
        cache_patcher = mock.patch.object(
            self.module,
            "DEFAULT_CACHE",
            self.cache,
        )
        cache_patcher.start()
        self.addCleanup(cache_patcher.stop)
        self.key.write_text("PRIVATE KEY PLACEHOLDER", encoding="utf-8")
        os.chmod(self.key, 0o600)
        self.known_hosts.write_text(
            "10.88.8.8 ssh-ed25519 AAAATEST", encoding="utf-8"
        )
        os.chmod(self.known_hosts, 0o600)
        private_write(
            self.credentials,
            {
                "schema": self.module.CREDENTIALS_SCHEMA,
                "email": "onion-sentinel-service@local.invalid",
                "password": "not-a-real-password-value",
            },
        )

    def config(self, **overrides):
        value = {
            "schema": self.module.CONFIG_SCHEMA,
            "enabled": True,
            "dataset": self.module.FIXED_DATASET,
            "relay_host": self.module.FIXED_RELAY_HOST,
            "relay_user": self.module.FIXED_RELAY_USER,
            "relay_port": 22,
            "ssh_key": str(self.key),
            "known_hosts": str(self.known_hosts),
            "credentials_file": str(self.credentials),
            "cache_file": str(self.cache),
            "cache_ttl_seconds": 300,
            "connect_timeout_seconds": 8,
            "timeout_seconds": 45,
            "max_response_bytes": 8 * 1024 * 1024,
            "max_stderr_bytes": 128 * 1024,
        }
        value.update(overrides)
        return value

    def config_file(self, **overrides) -> Path:
        path = self.root / "ac-hunter.json"
        private_write(path, self.config(**overrides))
        return path

    def status_map(self):
        return {
            name: {"status": "ok", "http_status": 200, "error": ""}
            for name, _params, _optional in self.module.COLLECTION_OPERATIONS
        }

    def normalized(self, pulled_at: str = "2026-07-31T12:00:00Z"):
        return self.module.normalize_collection(
            {
                "database": [
                    {
                        "name": self.module.FIXED_DATASET,
                        "ts_range": {
                            "min": "2026-07-30T12:00:00Z",
                            "max": "2026-07-31T12:00:00Z",
                        },
                    }
                ],
                "dashboard": [],
                "beacons": [],
                "beacons_sni": [],
                "beacons_proxy": [],
                "long_connections": [],
                "dns": [],
                "unexpected_ports": {"findings": []},
                "blacklist_ip": None,
                "strobe": None,
            },
            pulled_at=pulled_at,
            source_statuses=self.status_map(),
        )

    def test_load_config_requires_fixed_relay_and_owner_only_files(self) -> None:
        loaded = self.module.load_config(self.config_file())
        self.assertEqual(loaded["relay_host"], "10.88.8.8")
        self.assertEqual(loaded["relay_user"], "aj")
        self.assertEqual(loaded["dataset"], "security-onion-rolling")

        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError, "outside the fixed allowlist"
        ):
            self.module.load_config(
                self.config_file(relay_host="192.168.1.12")
            )

        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError,
            "outside the fixed runtime location",
        ):
            self.module.load_config(
                self.config_file(cache_file=str(self.root / "other.json"))
            )

        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError,
            "must be distinct",
        ):
            self.module.load_config(
                self.config_file(ssh_key=str(self.cache))
            )

        os.chmod(self.known_hosts, 0o644)
        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError, "owner-only"
        ):
            self.module.load_config(self.config_file())

    def test_credentials_are_strict_and_never_enter_config_result(self) -> None:
        loaded = self.module.load_config(self.config_file())
        serialized = json.dumps(loaded, default=str)
        self.assertNotIn("not-a-real-password-value", serialized)
        self.assertNotIn("onion-sentinel-service@", serialized)

        private_write(
            self.credentials,
            {
                "schema": self.module.CREDENTIALS_SCHEMA,
                "email": "service@example.invalid",
                "password": "secret",
                "unexpected": "field",
            },
        )
        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError, "schema"
        ):
            self.module.load_credentials(self.credentials)

    def test_transport_is_fixed_ssh_with_no_direct_ac_hunter_or_url_input(self) -> None:
        contract = self.module._dependency("ac_hunter_contract")
        captured = {}

        def runner(command, **kwargs):
            captured["command"] = list(command)
            captured["stdin"] = kwargs["stdin_text"]
            request = json.loads(kwargs["stdin_text"])
            response = {
                "contract": contract.CONTRACT,
                "request_id": request["request_id"],
                "ok": True,
                "status": 200,
                "content_type": "application/json",
                "headers": {"location": "", "set_cookie": []},
                "body": [],
                "duration_ms": 1,
                "error": "",
            }
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(response),
                stderr="",
            )

        transport = self.module.RelayTransport(
            self.config(), runner=runner, contract=contract
        )
        transport.call("database")
        command = captured["command"]
        self.assertEqual(command[0:3], ["/usr/bin/ssh", "-F", "/dev/null"])
        self.assertEqual(command[-1], "aj@10.88.8.8")
        self.assertNotIn("192.168.1.12", " ".join(command))
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertIn("GlobalKnownHostsFile=/dev/null", command)
        request = json.loads(captured["stdin"])
        self.assertEqual(set(request), {
            "contract", "request_id", "operation", "params", "headers", "body"
        })
        with self.assertRaises(Exception):
            transport.call("https://192.168.1.12/api/v0/database")

    def test_relay_diagnostic_does_not_echo_authentication_material(self) -> None:
        diagnostic = self.module._relay_diagnostic(
            json.dumps(
                {
                    "error": "Authorization: Bearer very-secret",
                    "body": "ignored",
                }
            ),
            "password=also-secret",
        )
        self.assertNotIn("very-secret", diagnostic)
        self.assertNotIn("also-secret", diagnostic)
        self.assertEqual(diagnostic, "the forced AC Hunter Relay request failed")

    def test_cookie_jwt_flow_and_one_authentication_retry(self) -> None:
        now = 1_785_500_000.0

        class FakeTransport:
            def __init__(self):
                self.calls = []
                self.api_attempts = 0

            def call(self, operation, **kwargs):
                self.calls.append((operation, kwargs))
                if operation == "login_form":
                    return {
                        "ok": True,
                        "status": 200,
                        "headers": {
                            "set_cookie": [
                                "session=preauth; Secure; HttpOnly; Path=/"
                            ]
                        },
                        "body": (
                            '<form><input name="csrf_token" value="csrf-value"></form>'
                        ),
                    }
                if operation == "login":
                    self.assert_login(kwargs)
                    return {
                        "ok": True,
                        "status": 302,
                        "headers": {
                            "set_cookie": [
                                "session=authenticated; Secure; HttpOnly; Path=/"
                            ]
                        },
                        "body": None,
                    }
                if operation == "jwt":
                    return {
                        "ok": True,
                        "status": 200,
                        "headers": {"set_cookie": []},
                        "body": {"token": jwt(now + 300)},
                    }
                self.api_attempts += 1
                if self.api_attempts == 1:
                    return {
                        "ok": True,
                        "status": 302,
                        "headers": {"set_cookie": []},
                        "body": None,
                    }
                return {
                    "ok": True,
                    "status": 200,
                    "headers": {"set_cookie": []},
                    "body": [{"name": "security-onion-rolling"}],
                }

            @staticmethod
            def assert_login(kwargs):
                assert kwargs["body"]["email"].endswith("@local.invalid")
                assert kwargs["body"]["password"] == "ephemeral"
                assert kwargs["body"]["csrf_token"] == "csrf-value"
                assert "session=preauth" in kwargs["headers"]["cookie"]

        transport = FakeTransport()
        credentials_calls = []

        def credentials():
            credentials_calls.append(True)
            return "service@local.invalid", "ephemeral"

        client = self.module.AcHunterApiClient(
            transport, credentials, clock=lambda: now
        )
        result = client.get("database")
        self.assertEqual(result[0]["name"], "security-onion-rolling")
        self.assertEqual(len(credentials_calls), 2)
        self.assertEqual(
            [name for name, _kwargs in transport.calls].count("login"), 2
        )
        api_headers = [
            kwargs["headers"]
            for name, kwargs in transport.calls
            if name == "database"
        ]
        self.assertTrue(
            all(value["authorization"].startswith("Bearer ") for value in api_headers)
        )
        self.assertFalse(
            hasattr(client, "password") or hasattr(client, "credentials")
        )

    def test_live_schema_normalization_scoring_and_correlations(self) -> None:
        raw = {
            "database": [
                {
                    "name": "security-onion-rolling",
                    "ts_range": {
                        "min": "2026-07-30T01:00:00Z",
                        "max": "2026-07-31T02:00:00Z",
                    },
                }
            ],
            "dashboard": [
                {
                    "ip": "10.66.6.209",
                    "score": 0.98,
                    "rare_sig_count": {"base": 12, "points": 10},
                },
                {"ip": "10.100.4.245", "score": 0.80},
            ],
            "beacons": [
                {
                    "src": "10.66.6.209",
                    "dst": "208.70.182.48",
                    "connection_count": 44,
                    "score": 0.97,
                    "ts_mode": "periodic",
                    "ds_mode": "stable",
                    "port": 1610,
                    "protocol": "TLS/unknown",
                },
                {
                    "src": "10.66.6.50",
                    "dst": "17.57.144.22",
                    "fqdn": "courier.push.apple.com",
                    "connection_count": 50,
                    "score": 0.99,
                    "port": 443,
                    "protocol": "TCP",
                },
            ],
            "beacons_sni": [
                {
                    "src": "10.66.6.209",
                    "fqdn": "unexplained.example",
                    "responding_ips": [{"ip": "203.0.113.50"}],
                    "connection_count": 22,
                    "score": 0.88,
                }
            ],
            "beacons_proxy": [],
            "long_connections": [
                {
                    "src": "10.100.4.245",
                    "dst": "98.84.79.102",
                    "duration": 22000,
                    "open": True,
                    "tuples": [{"resp_p": 443, "transport": "tcp"}],
                    "ptr": "ec2-98-84-79-102.compute.amazonaws.com",
                }
            ],
            "dns": [{"domain": "rare.example", "subdomains": 150, "visited": 2}],
            "unexpected_ports": {
                "findings": [
                    {
                        "source": "10.66.6.209",
                        "destination": "208.70.182.48",
                        "port": 1610,
                        "protocol": "TLS/unknown",
                        "count": 5,
                    }
                ]
            },
            "blacklist_ip": None,
            "strobe": None,
            "dashboard_count": {"count": 2},
            "dashboard_c2flag": {"count": 1},
            "beacons_count": 3,
            "certificate_count": {"count": 9},
            "useragent_count_false": 7,
            "useragent_count_true": 2,
        }
        value = self.module.normalize_collection(
            raw,
            pulled_at="2026-07-31T12:00:00Z",
            source_statuses=self.status_map(),
        )
        self.assertEqual(
            value["time_range"],
            {
                "start": "2026-07-30T01:00:00Z",
                "end": "2026-07-31T02:00:00Z",
            },
        )
        watch = value["modules"]["beacons"]["findings"][0]
        self.assertEqual(watch["verdict"], "Needs review")
        self.assertTrue(watch["watch_match"])
        self.assertIn("TCP/1610", watch["reason"])
        apple = value["modules"]["beacons"]["findings"][1]
        self.assertEqual(apple["verdict"], "Needs review")
        self.assertIn("Apple", apple["reason"])
        self.assertIn(
            "12 rare client-signature observations",
            watch["reason"],
        )
        sni = value["modules"]["beacons_sni"]["findings"][0]
        self.assertEqual(sni["responding_ips"], ["203.0.113.50"])
        long_connection = value["modules"]["long_connections"]["findings"][0]
        self.assertEqual(long_connection["port"], 443)
        self.assertEqual(long_connection["protocol"], "TCP")
        self.assertTrue(long_connection["watch_match"])
        self.assertEqual(long_connection["verdict"], "Needs review")
        correlation = next(
            item
            for item in value["correlated_hosts"]
            if item["source_ip"] == "10.66.6.209"
        )
        self.assertEqual(
            correlation["modules"],
            ["beacons", "beacons_sni", "unexpected_ports"],
        )
        top_host = next(
            item
            for item in value["top_hosts"]
            if item["source_ip"] == "10.66.6.209"
        )
        self.assertEqual(
            top_host["finding_count"],
            correlation["finding_count"],
        )
        self.assertTrue(
            any(note["watch_match"] for note in value["analyst_notes"])
        )
        self.assertIn("do not by themselves establish", value["disclaimer"])

    def test_named_vendor_services_and_apple_network_lower_priority(self) -> None:
        findings = (
            {
                "source_ip": "10.77.7.225",
                "destination_ip": "",
                "fqdn": "persistent.oaistatic.com",
                "module": "beacons_sni",
                "score": 0.99,
                "count": 25,
                "duration": 0,
                "duration_seconds": 0,
                "port": 443,
                "protocol": "TCP",
                "evidence": {},
            },
            {
                "source_ip": "192.168.100.14",
                "destination_ip": "",
                "fqdn": "go-updater.brave.com",
                "module": "beacons_sni",
                "score": 0.99,
                "count": 25,
                "duration": 0,
                "duration_seconds": 0,
                "port": 443,
                "protocol": "TCP",
                "evidence": {},
            },
            {
                "source_ip": "10.66.6.209",
                "destination_ip": "17.57.144.103",
                "fqdn": "",
                "module": "beacons",
                "score": 0.99,
                "count": 25,
                "duration": 0,
                "duration_seconds": 0,
                "port": 443,
                "protocol": "TCP",
                "evidence": {},
            },
        )
        for finding in findings:
            scored = self.module._score_finding(dict(finding), 1)
            self.assertEqual(scored["verdict"], "Needs review")
            self.assertIn("lowered priority", scored["reason"])

        for unsafe_hostname in (
            "evilapple.example",
            "malicious.googleusercontent.com",
        ):
            scored = self.module._score_finding(
                {
                    "source_ip": "10.77.7.225",
                    "destination_ip": "",
                    "fqdn": unsafe_hostname,
                    "module": "beacons_sni",
                    "score": 0.99,
                    "count": 25,
                    "duration": 0,
                    "duration_seconds": 0,
                    "port": 443,
                    "protocol": "TCP",
                    "evidence": {},
                },
                1,
            )
            self.assertNotEqual(scored["verdict"], "Likely benign")
            self.assertGreaterEqual(scored["priority_score"], 25)
            self.assertNotIn("lowered priority", scored["reason"])

    def test_collect_calls_every_named_endpoint_with_bounded_first_page(self) -> None:
        calls = []

        class Client:
            def get(self, operation, params):
                calls.append((operation, dict(params)))
                if operation in {"blacklist_ip", "strobe"}:
                    return None
                return []

        value = self.module.collect(Client(), lambda: 1_785_500_000.0)
        operations = [name for name, _params in calls]
        self.assertEqual(
            operations,
            [
                "database",
                "dashboard",
                "dashboard_count",
                "dashboard_c2flag",
                "beacons_count",
                "beacons",
                "beacons_sni",
                "beacons_proxy",
                "long_connections",
                "dns",
                "strobe",
                "blacklist_ip",
                "certificate_count",
                "useragent_count",
                "useragent_count",
                "unexpected_ports",
            ],
        )
        paged = [
            params
            for operation, params in calls
            if operation
            in {
                "beacons",
                "beacons_sni",
                "beacons_proxy",
                "long_connections",
                "dns",
                "strobe",
                "blacklist_ip",
            }
        ]
        self.assertTrue(all(item["page"] == 1 for item in paged))
        self.assertTrue(all(item["size"] == 100 for item in paged))
        self.assertTrue(value["ok"])

    def test_normalized_cache_is_atomic_private_and_rejects_secrets(self) -> None:
        payload = self.normalized()
        self.module.atomic_write_cache(self.cache, payload)
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o600)
        raw = self.cache.read_text(encoding="utf-8")
        self.assertNotIn("password", raw.lower())
        self.assertNotIn("authorization", raw.lower())
        self.assertEqual(
            self.module.load_cache(self.cache)["schema"],
            self.module.REVIEW_SCHEMA,
        )
        poisoned = self.normalized()
        poisoned["metadata"]["token"] = "secret"
        with self.assertRaisesRegex(
            self.module.AcHunterConfigurationError, "authentication material"
        ):
            self.module.atomic_write_cache(self.cache, poisoned)

    def test_fresh_cache_skips_collection_force_refreshes_and_stale_falls_back(self) -> None:
        now = [1_785_500_000.0]
        pulled_at = self.module._utc_iso(now[0])
        calls = []

        def collector(_client, _clock):
            calls.append(True)
            return self.normalized(pulled_at)

        service = self.module.AcHunterReviewService(
            self.config(),
            client=object(),
            clock=lambda: now[0],
            collector=collector,
        )
        status, first = service.response()
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 1)
        status, second = service.response()
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 1)
        self.assertEqual(second["cache"]["status"], "fresh")
        status, _forced = service.response(force_refresh=True)
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 1)
        self.assertTrue(_forced["cache"]["refresh_limited"])

        now[0] += self.module.MIN_FORCE_REFRESH_INTERVAL_SECONDS + 1
        status, _forced = service.response(force_refresh=True)
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 2)

        def fail(_client, _clock):
            raise self.module.AcHunterTransportError(
                "Authorization: Bearer should-never-be-returned"
            )

        service.collector = fail
        now[0] += self.module.MIN_FORCE_REFRESH_INTERVAL_SECONDS + 1
        status, stale = service.response(force_refresh=True)
        self.assertEqual(status, 200)
        self.assertTrue(stale["cache"]["stale"])
        serialized = json.dumps(stale)
        self.assertNotIn("should-never-be-returned", serialized)
        self.assertNotIn("Bearer", serialized)
        self.assertEqual(first["schema"], stale["schema"])

    def test_single_flight_refresh_collects_only_once_for_concurrent_gets(self) -> None:
        now = 1_785_500_000.0
        calls = []

        def collector(_client, _clock):
            calls.append(True)
            time.sleep(0.05)
            return self.normalized(self.module._utc_iso(now))

        service = self.module.AcHunterReviewService(
            self.config(),
            client=object(),
            clock=lambda: now,
            collector=collector,
        )
        responses = []

        def run():
            responses.append(service.response())

        threads = [threading.Thread(target=run) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(responses), 4)
        self.assertTrue(all(status == 200 for status, _payload in responses))

    def test_module_level_api_is_lazy_and_returns_sanitized_failure(self) -> None:
        self.module._DEFAULT_SERVICE = None
        missing = self.root / "missing-config.json"
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_AC_HUNTER_CONFIG": str(missing)},
            clear=False,
        ):
            status, payload = self.module.deep_review_response()
        self.assertEqual(status, 503)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["dataset"]["name"], "security-onion-rolling")
        self.assertIn("behavioral triage", payload["disclaimer"])


if __name__ == "__main__":
    unittest.main()
