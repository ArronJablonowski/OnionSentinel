#!/usr/bin/env python3
"""Contracts for bounded, read-only DHCP asset discovery."""
from __future__ import annotations

import datetime as dt
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import inspect
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "n8n" / "bin" / "collect-dhcp-asset-discovery.py"
QUERY_CLIENT = ROOT / "n8n" / "bin" / "query-security-onion.py"
PROMOTER = ROOT / "n8n" / "bin" / "promote-dhcp-asset.py"
WRAPPER = ROOT / "security-onion" / "bin" / "export-dhcp-observations"
BROKER = ROOT / "relay" / "app" / "incident_evidence_broker.py"
PORTAL = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
BUILDER = ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    for dependency in (ROOT / "n8n" / "bin", ROOT / "relay" / "app"):
        if str(dependency) not in sys.path:
            sys.path.insert(0, str(dependency))
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


class DhcpWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_module("dhcp_so_wrapper_test", WRAPPER)

    def test_contract_rejects_caller_dsl_and_long_windows(self) -> None:
        valid = {
            "contract": self.wrapper.CONTRACT,
            "operation": "dhcp_observations",
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:30:00Z",
            },
            "size": 1000,
        }
        start, end, size = self.wrapper.validate_request(
            valid,
            now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(size, 1000)
        self.assertLess(start, end)
        with self.assertRaises(ValueError):
            self.wrapper.validate_request(
                {**valid, "query": {"match_all": {}}},
                now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
            )
        too_long = json.loads(json.dumps(valid))
        too_long["window"]["start"] = "2026-07-28T16:59:00Z"
        with self.assertRaises(ValueError):
            self.wrapper.validate_request(
                too_long,
                now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
            )

    def test_zeek_observation_is_normalized_and_bounded(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "zeek": {
                    "dhcp": {
                        "assigned_addr": "10.66.6.210",
                        "host_name": "Studio.EXAMPLE.LAN.",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "msg_type": "ACK",
                        "lease_time": 3600,
                    }
                },
                "observer": {"name": "so-sensor-1"},
            }
        })
        self.assertEqual(result["ip_address"], "10.66.6.210")
        self.assertEqual(result["hostname"], "studio.example.lan")
        self.assertEqual(result["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["message_type"], "ACK")
        self.assertEqual(len(result["evidence_id"]), 24)

    def test_live_security_onion_ecs_observation_is_normalized(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "dhcp": {
                    "assigned_ip": ["10.66.6.210"],
                    "requested_address": "10.66.6.209",
                    "lease_time": 7200,
                    "message_types": ["ACK"],
                },
                "client": {"address": "10.66.6.208"},
                "server": {"address": "10.66.6.1"},
                "host": {
                    "mac": ["AA:BB:CC:DD:EE:FF"],
                    "hostname": "Studio.EXAMPLE.LAN.",
                },
                "observer": {"name": "so-sensor-1"},
            }
        })
        self.assertEqual(result["ip_address"], "10.66.6.210")
        self.assertEqual(result["hostname"], "studio.example.lan")
        self.assertEqual(result["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["message_type"], "ACK")
        self.assertEqual(result["lease_seconds"], 7200)

    def test_server_address_is_never_used_as_a_client_asset(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "server": {"address": "10.66.6.1"},
                "host": {"mac": ["AA:BB:CC:DD:EE:FF"]},
            }
        })
        self.assertIsNone(result)

    def test_source_uses_search_only_and_fixed_dataset(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('INDEX = "logs-zeek-so"', source)
        self.assertIn('DATASET = "zeek.dhcp"', source)
        self.assertIn('endpoint = f"{INDEX}/_search"', source)
        self.assertNotIn("/_update", source)
        self.assertNotIn("/_delete", source)
        self.assertNotIn("/_bulk", source)
        for field in (
            "dhcp.assigned_ip",
            "dhcp.requested_address",
            "dhcp.lease_time",
            "dhcp.message_types",
            "host.mac",
            "client.address",
        ):
            self.assertIn(field, self.wrapper.SOURCE_FIELDS)
        self.assertNotIn("server.address", self.wrapper.SOURCE_FIELDS)
        incident_source = (
            ROOT / "security-onion" / "bin" / "export-incident-evidence"
        ).read_text(encoding="utf-8")
        self.assertIn("DHCP_DISCOVERY_CONTRACT", incident_source)
        self.assertIn("execute_dhcp_discovery(request_data)", incident_source)


class DhcpRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.broker = load_module("dhcp_relay_broker_test", BROKER)

    def test_relay_revalidates_the_fixed_contract(self) -> None:
        request = {
            "contract": self.broker.DHCP_DISCOVERY_CONTRACT,
            "operation": "dhcp_observations",
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:15:00Z",
            },
            "size": 500,
        }
        self.broker.validate_dhcp_request(request)
        with self.assertRaises(ValueError):
            self.broker.validate_dhcp_request({**request, "index": "*"})


class DhcpCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = load_module("dhcp_collector_test", COLLECTOR)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def observation(
        self,
        *,
        observed_at: str,
        address: str,
        mac: str,
        hostname: str,
        evidence_id: str,
    ) -> dict:
        return {
            "observed_at": observed_at,
            "ip_address": address,
            "mac_address": mac,
            "hostname": hostname,
            "message_type": "ACK",
            "lease_seconds": 3600,
            "sensor": "so-sensor-1",
            "evidence_id": evidence_id,
        }

    def test_public_compatibility_surface_and_signatures_are_stable(self) -> None:
        expected = {
            "asset_store_token": "(path: 'Path') -> 'str'",
            "persist_database_state": "(api_url: 'str', token: 'str', state: 'dict') -> 'dict'",
            "utc_now": "() -> 'dt.datetime'",
            "parse_timestamp": "(value: 'object') -> 'dt.datetime'",
            "format_timestamp": "(value: 'dt.datetime') -> 'str'",
            "bounded_json": "(path: 'Path', maximum_bytes: 'int') -> 'object'",
            "load_config": "(path: 'Path') -> 'dict'",
            "empty_state": "(status: 'str' = 'never_run') -> 'dict'",
            "load_state": "(path: 'Path') -> 'dict'",
            "atomic_write_json": "(path: 'Path', payload: 'dict') -> 'None'",
            "validate_response": "(payload: 'object', expected_window: 'dict | None' = None) -> 'dict'",
            "observation_identity": "(item: 'dict') -> 'tuple[str, str]'",
            "merge_observations": "(state: 'dict', incoming: 'list[dict]', now: 'dt.datetime', retention_days: 'int') -> 'list[dict]'",
            "collection_window": "(state: 'dict', now: 'dt.datetime', default_minutes: 'int') -> 'tuple[dt.datetime, dt.datetime]'",
            "query_dhcp": "(config: 'dict', start: 'dt.datetime', end: 'dt.datetime', size: 'int') -> 'dict'",
            "relay_failure_diagnostic": "(stdout: 'object', stderr: 'object') -> 'str'",
            "query_complete_window": "(config: 'dict', start: 'dt.datetime', end: 'dt.datetime', size: 'int', *, max_segments: 'int' = 16) -> 'dict'",
            "backfill": "(config: 'dict', state: 'dict', now: 'dt.datetime', days: 'int') -> 'dict'",
            "collect": "(config: 'dict', state: 'dict', now: 'dt.datetime') -> 'dict'",
            "main": "() -> 'int'",
        }
        self.assertEqual(
            {name: str(inspect.signature(getattr(self.collector, name))) for name in expected},
            expected,
        )
        self.assertEqual(self.collector.CONTRACT, "onion-sentinel-dhcp-asset-discovery-v1")
        self.assertEqual(self.collector.STATE_SCHEMA, "onion-sentinel-dhcp-asset-observations-v1")

    def test_asset_store_token_requires_owner_only_file_and_prefers_dedicated_token(self) -> None:
        environment = self.root / ".env"
        environment.write_text(
            "ASSET_STORE_WRITE_TOKEN=" + "a" * 32 + "\n"
            "N8N_POST_COMMIT_TOKEN=" + "b" * 32 + "\n",
            encoding="utf-8",
        )
        environment.chmod(0o600)
        self.assertEqual(self.collector.asset_store_token(environment), "a" * 32)
        environment.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "owner-controlled"):
            self.collector.asset_store_token(environment)

    def test_main_persists_database_before_publishing_cache(self) -> None:
        state_path = self.root / "state.json"
        log_path = self.root / "collector.jsonl"
        updated = self.collector.empty_state()
        updated["observations"] = [{"discovery_id": "a" * 20}]
        updated["collection"].update({
            "status": "ok",
            "last_returned": 1,
            "last_truncated": False,
        })
        calls = []

        def persist(_url: str, token: str, state: dict) -> dict:
            calls.append(("persist", token, state))
            return {"ok": True, "retained": 1}

        def publish(path: Path, state: dict) -> None:
            calls.append(("publish", path, state))

        with mock.patch.object(
            sys,
            "argv",
            [
                "collector",
                "--config", str(self.root / "config.json"),
                "--state", str(state_path),
                "--log", str(log_path),
                "--env", str(self.root / ".env"),
                "--require-database",
            ],
        ), mock.patch.object(
            self.collector, "load_config", return_value={"enabled": True}
        ), mock.patch.object(
            self.collector, "load_state", return_value=self.collector.empty_state()
        ), mock.patch.object(
            self.collector, "collect", return_value=updated
        ), mock.patch.object(
            self.collector, "asset_store_token", return_value="t" * 32
        ), mock.patch.object(
            self.collector, "persist_database_state", side_effect=persist
        ), mock.patch.object(
            self.collector, "atomic_write_json", side_effect=publish
        ):
            self.assertEqual(self.collector.main(), 0)

        self.assertEqual([call[0] for call in calls], ["persist", "publish"])
        self.assertIs(calls[0][2], updated)
        self.assertIs(calls[1][2], updated)

    def test_main_database_failure_records_failed_state_but_never_publishes_candidate(self) -> None:
        state_path = self.root / "state.json"
        log_path = self.root / "collector.jsonl"
        original = self.collector.empty_state()
        candidate = self.collector.empty_state()
        candidate["observations"] = [{"discovery_id": "candidate"}]
        candidate["collection"].update({
            "status": "ok",
            "last_returned": 1,
            "last_truncated": False,
        })
        published = []

        with mock.patch.object(
            sys,
            "argv",
            [
                "collector",
                "--config", str(self.root / "config.json"),
                "--state", str(state_path),
                "--log", str(log_path),
                "--env", str(self.root / ".env"),
                "--require-database",
            ],
        ), mock.patch.object(
            self.collector, "load_config", return_value={"enabled": True}
        ), mock.patch.object(
            self.collector, "load_state", side_effect=[original, original]
        ), mock.patch.object(
            self.collector, "collect", return_value=candidate
        ), mock.patch.object(
            self.collector, "asset_store_token", return_value="t" * 32
        ), mock.patch.object(
            self.collector,
            "persist_database_state",
            side_effect=RuntimeError("database unavailable"),
        ), mock.patch.object(
            self.collector,
            "atomic_write_json",
            side_effect=lambda _path, state: published.append(state),
        ):
            self.assertEqual(self.collector.main(), 1)

        self.assertEqual(len(published), 1)
        self.assertNotIn({"discovery_id": "candidate"}, published[0]["observations"])
        self.assertEqual(published[0]["collection"]["status"], "failed")
        self.assertIn("database unavailable", published[0]["collection"]["last_error"])

    def test_merge_tracks_ip_movement_by_mac_without_promoting_inventory(self) -> None:
        now = dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)
        merged = self.collector.merge_observations(
            self.collector.empty_state(),
            [
                self.observation(
                    observed_at="2026-07-29T17:00:00Z",
                    address="10.66.6.210",
                    mac="aa:bb:cc:dd:ee:ff",
                    hostname="studio.example.lan",
                    evidence_id="a" * 24,
                ),
                self.observation(
                    observed_at="2026-07-29T17:30:00Z",
                    address="10.66.6.211",
                    mac="aa:bb:cc:dd:ee:ff",
                    hostname="studio.example.lan",
                    evidence_id="b" * 24,
                ),
            ],
            now,
            30,
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["current_ip"], "10.66.6.211")
        self.assertEqual(merged[0]["ip_addresses"], ["10.66.6.210", "10.66.6.211"])
        self.assertEqual(merged[0]["observation_count"], 2)
        self.assertNotIn("authoritative", merged[0])

    def test_disabled_collector_writes_timestamped_state_without_ssh(self) -> None:
        config = self.root / "config.json"
        state = self.root / "state.json"
        log = self.root / "collector.jsonl"
        config.write_text(json.dumps({
            "enabled": False,
            "host": "10.88.8.8",
            "ssh_user": "aj",
            "ssh_key": str(self.root / "key"),
            "known_hosts": str(self.root / "known_hosts"),
            "connect_timeout_seconds": 20,
            "timeout_seconds": 90,
            "max_response_bytes": 4194304,
            "max_stderr_bytes": 131072,
            "query_window_minutes": 30,
            "query_size": 1000,
            "retention_days": 30,
        }), encoding="utf-8")
        with mock.patch.object(
            sys,
            "argv",
            ["collector", "--config", str(config), "--state", str(state), "--log", str(log)],
        ), mock.patch.object(
            self.collector,
            "run_bounded_command",
            side_effect=AssertionError("SSH must not run while disabled"),
        ):
            self.assertEqual(self.collector.main(), 0)
        payload = json.loads(state.read_text(encoding="utf-8"))
        record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(payload["collection"]["status"], "disabled")
        self.assertTrue(payload["collection"]["last_attempt_at"].endswith("Z"))
        self.assertTrue(record["timestamp"].endswith("Z"))
        self.assertEqual(record["event"], "dhcp_asset_discovery.disabled")

    def test_query_uses_current_bounded_process_text_contract(self) -> None:
        start = dt.datetime(2026, 7, 29, 17, tzinfo=dt.timezone.utc)
        end = start + dt.timedelta(minutes=30)
        response = {
            "ok": True,
            "contract": self.collector.CONTRACT,
            "generated_at": "2026-07-29T17:30:01.000Z",
            "status": "ok",
            "window": {
                "start": "2026-07-29T17:00:00.000Z",
                "end": "2026-07-29T17:30:00.000Z",
            },
            "hits_total": 0,
            "returned": 0,
            "truncated": False,
            "query_audit": {
                "index": "logs-zeek-so",
                "dataset": "zeek.dhcp",
                "query_digest": "a" * 64,
            },
            "observations": [],
        }
        config = {
            "host": "10.88.8.8",
            "ssh_user": "aj",
            "ssh_key": str(self.root / "key"),
            "known_hosts": str(self.root / "known_hosts"),
            "connect_timeout_seconds": 20,
            "timeout_seconds": 120,
            "max_response_bytes": 4 * 1024 * 1024,
            "max_stderr_bytes": 128 * 1024,
        }
        runner = mock.Mock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps(response),
                stderr="",
            )
        )
        with mock.patch.object(
            self.collector,
            "run_bounded_command",
            runner,
        ), mock.patch.object(
            self.collector,
            "utc_now",
            return_value=end,
        ):
            result = self.collector.query_dhcp(config, start, end, 1000)

        self.assertEqual(result["returned"], 0)
        kwargs = runner.call_args.kwargs
        self.assertIsInstance(kwargs["stdin_text"], str)
        self.assertNotIn("input_bytes", kwargs)
        request = json.loads(kwargs["stdin_text"])
        self.assertEqual(request["operation"], "dhcp_observations")
        self.assertEqual(
            request["window"],
            response["window"],
        )

    def test_relay_failure_uses_only_bounded_envelope_diagnostics(self) -> None:
        diagnostic = self.collector.relay_failure_diagnostic(
            json.dumps({
                "ok": False,
                "error": "restricted command failed",
                "upstream_error": "DHCP helper unavailable",
                "ignored": "10.66.6.210",
            }),
            "",
        )
        self.assertIn("restricted command failed", diagnostic)
        self.assertIn("DHCP helper unavailable", diagnostic)
        self.assertNotIn("10.66.6.210", diagnostic)

    def test_truncated_bootstrap_splits_windows_and_advances_only_when_complete(self) -> None:
        start = dt.datetime(2026, 7, 29, 0, tzinfo=dt.timezone.utc)
        end = start + dt.timedelta(hours=24)

        def response(segment_start: dt.datetime, segment_end: dt.datetime, truncated: bool) -> dict:
            identifier = hashlib.sha256(
                self.collector.format_timestamp(segment_start).encode("utf-8")
            ).hexdigest()[:24]
            return {
                "status": "ok",
                "window": {
                    "start": self.collector.format_timestamp(segment_start),
                    "end": self.collector.format_timestamp(segment_end),
                },
                "hits_total": 1001 if truncated else 1,
                "observations": [self.observation(
                    observed_at=self.collector.format_timestamp(
                        segment_start + dt.timedelta(seconds=1)
                    ),
                    address="10.66.6.210",
                    mac="aa:bb:cc:dd:ee:ff",
                    hostname="studio.example.lan",
                    evidence_id=identifier,
                )],
                "truncated": truncated,
            }

        calls = []

        def query(_config: dict, segment_start: dt.datetime, segment_end: dt.datetime, _size: int) -> dict:
            calls.append((segment_start, segment_end))
            return response(
                segment_start,
                segment_end,
                truncated=(segment_end - segment_start) > dt.timedelta(hours=12),
            )

        with mock.patch.object(self.collector, "query_dhcp", side_effect=query):
            result = self.collector.query_complete_window({}, start, end, 1000)

        self.assertEqual(len(calls), 3)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["truncated"])
        self.assertEqual(result["query_segments"], 3)
        self.assertEqual(len(result["observations"]), 2)

    def test_incomplete_coverage_does_not_advance_success_checkpoint(self) -> None:
        now = dt.datetime(2026, 7, 30, 0, tzinfo=dt.timezone.utc)
        state = self.collector.empty_state()
        state["collection"]["last_success_at"] = "2026-07-29T23:30:00.000Z"
        incomplete = {
            "status": "partial",
            "window": {
                "start": "2026-07-29T23:25:00.000Z",
                "end": "2026-07-30T00:00:00.000Z",
            },
            "hits_total": 1001,
            "observations": [],
            "truncated": True,
            "query_segments": self.collector.MAX_QUERY_SEGMENTS,
        }
        config = {
            "query_window_minutes": 1440,
            "query_size": 1000,
            "retention_days": 30,
        }
        with mock.patch.object(
            self.collector,
            "query_complete_window",
            return_value=incomplete,
        ):
            result = self.collector.collect(config, state, now)

        self.assertEqual(result["collection"]["status"], "partial")
        self.assertEqual(
            result["collection"]["last_success_at"],
            "2026-07-29T23:30:00.000Z",
        )
        self.assertIn("checkpoint was not advanced", result["collection"]["last_error"])
        self.assertEqual(
            result["collection"]["last_query_segments"],
            self.collector.MAX_QUERY_SEGMENTS,
        )

    def test_backfill_merges_daily_windows_without_moving_live_checkpoint(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        state = self.collector.empty_state()
        state["collection"]["last_success_at"] = "2026-07-30T17:45:00.000Z"
        config = {"query_size": 1000, "retention_days": 30}
        calls = []

        def query(
            _config: dict,
            start: dt.datetime,
            end: dt.datetime,
            _size: int,
            *,
            max_segments: int,
        ) -> dict:
            calls.append((start, end, max_segments))
            identifier = hashlib.sha256(
                self.collector.format_timestamp(start).encode("utf-8")
            ).hexdigest()[:24]
            return {
                "status": "ok",
                "window": {
                    "start": self.collector.format_timestamp(start),
                    "end": self.collector.format_timestamp(end),
                },
                "hits_total": 1,
                "observations": [self.observation(
                    observed_at=self.collector.format_timestamp(
                        start + dt.timedelta(seconds=1)
                    ),
                    address=f"10.66.6.{100 + len(calls)}",
                    mac=f"aa:bb:cc:dd:ee:{len(calls):02x}",
                    hostname=f"host-{len(calls)}",
                    evidence_id=identifier,
                )],
                "truncated": False,
                "query_segments": 1,
            }

        with mock.patch.object(
            self.collector,
            "query_complete_window",
            side_effect=query,
        ):
            result = self.collector.backfill(config, state, now, 3)

        self.assertEqual(len(calls), 3)
        self.assertEqual(result["backfill"]["status"], "ok")
        self.assertEqual(result["backfill"]["last_query_segments"], 3)
        self.assertEqual(len(result["observations"]), 3)
        self.assertEqual(
            result["collection"]["last_success_at"],
            "2026-07-30T17:45:00.000Z",
        )

    def test_backfill_stops_on_incomplete_window(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        response = {
            "status": "partial",
            "window": {
                "start": "2026-07-28T18:00:00.000Z",
                "end": "2026-07-29T18:00:00.000Z",
            },
            "hits_total": 1001,
            "observations": [],
            "truncated": True,
            "query_segments": 16,
        }
        with mock.patch.object(
            self.collector,
            "query_complete_window",
            return_value=response,
        ):
            result = self.collector.backfill(
                {"query_size": 1000, "retention_days": 30},
                self.collector.empty_state(),
                now,
                2,
            )

        self.assertEqual(result["backfill"]["status"], "partial")
        self.assertFalse(result["backfill"]["last_success_at"])
        self.assertIn("incomplete", result["backfill"]["last_error"])


class SecurityOnionQueryClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.query_client = load_module("security_onion_query_client_test", QUERY_CLIENT)

    def test_manual_query_runs_while_scheduled_collection_is_disabled(self) -> None:
        fake_client = mock.Mock()
        now = dt.datetime(2026, 7, 29, 21, tzinfo=dt.timezone.utc)
        fake_client.utc_now.return_value = now
        fake_client.load_config.return_value = {
            "enabled": False,
            "host": "10.88.8.8",
        }
        fake_client.query_dhcp.return_value = {
            "ok": True,
            "contract": "onion-sentinel-dhcp-asset-discovery-v1",
            "generated_at": "2026-07-29T21:00:00.000Z",
            "status": "ok",
            "window": {
                "start": "2026-07-29T20:45:00.000Z",
                "end": "2026-07-29T21:00:00.000Z",
            },
            "hits_total": 2,
            "returned": 1,
            "truncated": False,
            "query_audit": {
                "index": "logs-zeek-so",
                "dataset": "zeek.dhcp",
                "query_digest": "a" * 64,
            },
            "observations": [{
                "ip_address": "10.66.6.210",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "query.jsonl"
            stdout = io.StringIO()
            with mock.patch.object(
                self.query_client,
                "load_dhcp_client",
                return_value=fake_client,
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "query-security-onion",
                    "--log",
                    str(log),
                    "dhcp",
                    "--minutes",
                    "15",
                    "--size",
                    "25",
                    "--summary",
                ],
            ), contextlib.redirect_stdout(stdout):
                self.assertEqual(self.query_client.main(), 0)
            fake_client.query_dhcp.assert_called_once_with(
                fake_client.load_config.return_value,
                now - dt.timedelta(minutes=15),
                now,
                25,
            )
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["hits_total"], 2)
            self.assertNotIn("observations", output)
            record = json.loads(log.read_text(encoding="utf-8"))
            self.assertTrue(record["timestamp"].endswith("Z"))
            self.assertEqual(record["event"], "security_onion_query.completed")
            self.assertNotIn("10.66.6.210", json.dumps(record))


class DhcpAssetPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.promoter = load_module("dhcp_asset_promoter_test", PROMOTER)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "asset_inventory.json"
        self.state = self.root / "dhcp-observations.json"
        self.inventory.write_text(json.dumps({
            "schema": "onion-sentinel-asset-inventory-v1",
            "version": 1,
            "generated_at": "2026-07-29T00:00:00Z",
            "assets": [],
        }), encoding="utf-8")
        self.state.write_text(json.dumps({
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "version": 1,
            "updated_at": "2026-07-30T18:00:00Z",
            "collection": {"status": "ok"},
            "observations": [{
                "discovery_id": "a" * 20,
                "current_ip": "10.66.6.210",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "reserved-client",
                "last_seen": "2026-07-30T17:55:00Z",
                "lease_expires_at": "2026-07-31T17:55:00Z",
                "observation_count": 12,
            }],
        }), encoding="utf-8")
        self.inventory.chmod(0o600)
        self.state.chmod(0o600)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def args(self, **overrides):
        values = {
            "inventory": self.inventory,
            "state": self.state,
            "discovery_id": "a" * 20,
            "expected_ip": "10.66.6.210",
            "expected_mac": "00:11:22:33:44:55",
            "expected_hostname": "reserved-client",
            "asset_id": "reserved-client",
            "hostname": "",
            "role": "Reviewed LAN client",
            "platform": "",
            "owner_ref": "operator-reviewed",
            "criticality": "unknown",
            "accept_locally_administered_mac": False,
            "confirm": f"PROMOTE:{'a' * 20}",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_explicit_promotion_is_validated_backed_up_and_atomic(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        result, backup = self.promoter.promote(self.args(), now)
        payload = json.loads(self.inventory.read_text(encoding="utf-8"))
        self.assertEqual(result["asset_id"], "reserved-client")
        self.assertEqual(result["mac_address_scope"], "globally_administered")
        self.assertTrue(backup.is_file())
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(payload["assets"][0]["identifiers"]["ip_addresses"], ["10.66.6.210"])
        self.assertEqual(payload["assets"][0]["identifiers"]["mac_addresses"], ["00:11:22:33:44:55"])
        self.assertEqual(payload["assets"][0]["source_type"], "operator-approved-dhcp")
        self.assertFalse(payload["assets"][0]["share_with_hosted_models"])

    def test_promotion_rejects_changed_identity_and_private_mac_without_override(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(ValueError, "changed after operator review"):
            self.promoter.promote(
                self.args(expected_ip="10.66.6.211"),
                now,
            )
        payload = json.loads(self.state.read_text(encoding="utf-8"))
        payload["observations"][0]["mac_address"] = "02:11:22:33:44:55"
        self.state.write_text(json.dumps(payload), encoding="utf-8")
        self.state.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "locally administered"):
            self.promoter.promote(
                self.args(expected_mac="02:11:22:33:44:55"),
                now,
            )


class DhcpDiscoveryApiAndPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.portal = load_module("dhcp_portal_test", PORTAL)
        self.portal.ASSET_INVENTORY_FILE = self.root / "asset_inventory.json"
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = self.root / "dhcp-observations.json"
        self.portal.ASSET_INVENTORY_CACHE = {"signature": None, "inventory": None}
        self.portal.ASSET_INVENTORY_FILE.write_text(json.dumps({
            "schema": "onion-sentinel-asset-inventory-v1",
            "version": 1,
            "generated_at": "2026-07-29T12:00:00-06:00",
            "assets": [{
                "asset_id": "studio",
                "valid_from": "2026-07-01T00:00:00-06:00",
                "valid_until": None,
                "identifiers": {
                    "ip_addresses": ["10.66.6.210"],
                    "hostnames": ["studio.example.lan"],
                    "mac_addresses": [],
                },
                "role": "workstation",
                "platform": "macOS",
                "criticality": "medium",
                "source_type": "operator-verified",
                "source_ref": "ticket",
                "confidence": "high",
                "owner_ref": "",
                "expected_services": [],
                "expected_behaviors": [],
                "share_with_hosted_models": False,
            }],
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_api_classifies_match_candidate_and_conflict(self) -> None:
        def record(identifier: str, ip: str, hostname: str) -> dict:
            return {
                "discovery_id": identifier,
                "identity_type": "hostname",
                "identity_value": hostname,
                "current_ip": ip,
                "ip_addresses": [ip],
                "mac_address": "",
                "hostname": hostname,
                "hostnames": [hostname],
                "first_seen": "2026-07-29T17:00:00Z",
                "last_seen": "2026-07-29T17:30:00Z",
                "lease_expires_at": "2026-07-29T18:30:00Z",
                "message_types": ["ACK"],
                "sensors": ["so-sensor-1"],
                "evidence_ids": ["a" * 24],
                "observation_count": 1,
            }
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE.write_text(json.dumps({
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "version": 1,
            "updated_at": "2026-07-29T17:30:00Z",
            "collection": {"status": "ok", "last_success_at": "2026-07-29T17:30:00Z"},
            "observations": [
                record("match", "10.66.6.210", "studio.example.lan"),
                record("conflict", "10.66.6.210", "other.example.lan"),
                record("candidate", "10.66.6.220", "new.example.lan"),
                record("moved", "10.66.6.211", "studio.example.lan"),
            ],
        }), encoding="utf-8")
        status, payload = self.portal.dhcp_asset_discovery_response(
            observed_at=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["counts"]["verified_match"], 2)
        self.assertEqual(payload["counts"]["conflict"], 1)
        self.assertEqual(payload["counts"]["candidate"], 1)
        self.assertEqual(payload["observations"][0]["reconciliation"], "conflict")
        moved = next(
            item
            for item in payload["observations"]
            if item["discovery_id"] == "moved"
        )
        self.assertEqual(moved["reconciliation"], "verified_match")
        self.assertIn("new current address", moved["reconciliation_detail"])
        self.assertEqual(payload["backfill"]["status"], "never_run")
        self.assertEqual(
            moved["authoritative_asset"]["configured_ip_addresses"],
            ["10.66.6.210"],
        )
        self.assertNotIn("owner_ref", json.dumps(payload))

    def test_page_route_scheduler_and_installers_are_wired(self) -> None:
        builder = load_module("dhcp_builder_test", BUILDER)
        builder.DB_PATH = self.root / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = self.root / "pcap"
        page = builder.render_static_page(builder.build_html([]), "asset_inventory", [])
        self.assertIn("DHCP network discovery", page)
        self.assertIn("fetch('/api/dhcp-asset-discovery'", page)
        self.assertIn(
            "Candidates and conflicts remain non-authoritative",
            page,
        )
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("collect-dhcp-asset-discovery.py", installer)
        self.assertIn("query-security-onion.py", installer)
        self.assertIn("promote-dhcp-asset.py", installer)
        self.assertIn("com.arron.soc.dhcp-asset-discovery.plist", installer)
        config = (
            ROOT / "n8n" / "config" / "dhcp-asset-discovery.example.json"
        ).read_text(encoding="utf-8")
        self.assertIn("onion-sentinel-incident-evidence_ed25519", config)
        self.assertNotIn("onion-sentinel-dhcp-discovery_ed25519", config)
        self.assertIn('"query_window_minutes": 1440', config)
        plist = (ROOT / "n8n" / "launchd" / "com.arron.soc.dhcp-asset-discovery.plist").read_text(encoding="utf-8")
        self.assertIn("<integer>900</integer>", plist)


if __name__ == "__main__":
    unittest.main()
