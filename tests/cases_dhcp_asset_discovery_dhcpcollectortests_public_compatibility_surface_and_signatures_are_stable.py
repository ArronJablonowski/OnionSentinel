from __future__ import annotations

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class DhcpCollectorTestsPublicCompatibilitySurfaceAndSignaturesAreStableCases:
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


    def test_collector_facade_starts_from_an_isolated_flat_bin(self) -> None:
        names = (
            "bounded_process.py",
            "bounded_process_io.py",
            "bounded_process_observation.py",
            "bounded_process_policy.py",
            "bounded_process_runtime.py",
            "bounded_process_termination.py",
            "security_jsonl_log.py",
            "dhcp_asset_contract.py",
            "dhcp_asset_state.py",
            "dhcp_asset_adapters.py",
            "dhcp_asset_workflow.py",
            "collect-dhcp-asset-discovery.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            for name in names:
                shutil.copy2(ROOT / "n8n" / "bin" / name, runtime / name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(runtime / "collect-dhcp-asset-discovery.py"),
                    "--help",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--require-database", result.stdout)
        self.assertIn("--backfill-days", result.stdout)


