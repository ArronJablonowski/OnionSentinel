from __future__ import annotations

from live_osquery_contract_fixtures import (
    BIN,
    BoundedProcessError,
    LiveOsqueryClientError,
    LiveOsqueryContractError,
    Path,
    RELAY_AUTHORIZED_KEY,
    RELAY_BROKER,
    RELAY_INSTALLER,
    RELAY_LAUNCHER,
    RELAY_SUDOERS,
    ROOT,
    SO_AUTHORIZED_KEY,
    SO_CONFIG_EXAMPLE,
    SO_INSTALLER,
    SO_LAUNCHER,
    SO_WRAPPER,
    SimpleNamespace,
    ThreadPoolExecutor,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    dt,
    harness_operator_approved,
    importlib,
    io,
    json,
    load_live_osquery_config,
    load_relay_broker,
    load_security_onion_wrapper,
    mock,
    normalize_query,
    normalize_requests,
    os,
    scheduled_inventory_approved,
    stat,
    subprocess,
    sys,
    tempfile,
    time,
    unittest,
    urllib,
    validate_result_artifact,
)

class LiveOsqueryClientConfigTestsCapabilityExposesOnlyExplicitDarwinSchemasCases:
    def test_capability_exposes_only_explicit_darwin_schemas(self):
        descriptor = capability_descriptor(
            {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
            }
        )
        self.assertEqual(descriptor["target_platform"], "darwin")
        self.assertEqual(descriptor["osquery_version"], "5.15.0")
        self.assertEqual(
            descriptor["table_schemas"]["system_info"][:2],
            ["board_model", "board_serial"],
        )
        self.assertIn("osquery_info", descriptor["allowed_tables"])
        self.assertIn("os_version", descriptor["allowed_tables"])
        self.assertIn("apps", descriptor["allowed_tables"])
        self.assertIn("bundle_identifier", descriptor["table_schemas"]["apps"])
        for unsafe_or_non_darwin in ("deb_packages", "rpm_packages", "suid_bin"):
            self.assertNotIn(unsafe_or_non_darwin, descriptor["allowed_tables"])
        self.assertIn("SELECT * is forbidden", descriptor["restrictions"])


    def test_time_bounded_operator_approval_is_alias_scoped(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            identity = root / "identity"
            known_hosts = root / "known_hosts"
            identity.write_text("private-key-placeholder", encoding="utf-8")
            known_hosts.write_text("host-key-placeholder", encoding="utf-8")
            config_path = root / "live-osquery.json"
            config_path.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "relay_host": "10.88.8.8",
                        "relay_user": "aj",
                        "identity_file": str(identity),
                        "known_hosts": str(known_hosts),
                        "allowed_target_aliases": ["endpoint-a"],
                        "target_bindings": {
                            "endpoint-a": {
                                "ips": ["192.0.2.10"],
                                "hosts": ["endpoint-a.example"],
                            }
                        },
                        "allowed_agent_roles": ["incident-responder"],
                        "harness_operator_approval": {
                            "approved": True,
                            "expires_at": "2099-01-01T00:00:00Z",
                            "target_aliases": ["endpoint-a"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            config = load_live_osquery_config(config_path)

        self.assertTrue(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-b",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertEqual(
            config["target_bindings"]["endpoint-a"]["ips"],
            ["192.0.2.10"],
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc),
            )
        )


    def test_scheduled_inventory_approval_is_independent_and_alias_scoped(self):
        config = {
            "enabled": True,
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
            },
        }
        self.assertTrue(scheduled_inventory_approved(config, "endpoint-a"))
        self.assertFalse(scheduled_inventory_approved(config, "endpoint-b"))


    def test_enabled_config_requires_safe_target_asset_bindings(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            identity = root / "identity"
            known_hosts = root / "known_hosts"
            identity.write_text("private-key-placeholder", encoding="utf-8")
            known_hosts.write_text("host-key-placeholder", encoding="utf-8")
            base = {
                "enabled": True,
                "relay_host": "10.88.8.8",
                "relay_user": "aj",
                "identity_file": str(identity),
                "known_hosts": str(known_hosts),
                "allowed_target_aliases": ["endpoint-a"],
            }
            for binding, message in (
                ({}, "trusted asset binding"),
                (
                    {"endpoint-a": {"ips": ["not-an-ip"]}},
                    "invalid IP",
                ),
                (
                    {"endpoint-b": {"ips": ["192.0.2.10"]}},
                    "unconfigured aliases",
                ),
            ):
                config_path = root / "live-osquery.json"
                config_path.write_text(
                    json.dumps({**base, "target_bindings": binding}),
                    encoding="utf-8",
                )
                config_path.chmod(0o600)
                with self.subTest(binding=binding):
                    with self.assertRaisesRegex(
                        LiveOsqueryClientError,
                        message,
                    ):
                        load_live_osquery_config(config_path)


    def test_config_rejects_insecure_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            source.chmod(0o644)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "mode 0600",
            ):
                load_live_osquery_config(source)
            source.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(source)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "regular file",
            ):
                load_live_osquery_config(link)


    def test_config_rejects_string_false_enabled_value(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "live-osquery.json"
            path.write_text('{"enabled":"false"}', encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "enabled must be boolean",
            ):
                load_live_osquery_config(path)


    def test_collector_enforces_approval_before_transport(self):
        config = {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "harness_operator_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
                "expires_at": "2000-01-01T00:00:00Z",
            },
        }
        with (
            mock.patch(
                "live_osquery_client.run_bounded_command",
                side_effect=AssertionError("transport must not run"),
            ),
            self.assertRaisesRegex(LiveOsqueryClientError, "approval"),
        ):
            collect_live_osquery(
                case_id="case-1",
                requests=[
                    {
                        "target_alias": "endpoint-a",
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "purpose": "verify endpoint",
                    }
                ],
                config=config,
                persist=False,
            )


    def test_collector_preserves_broker_timeout_failure_code(self):
        with tempfile.TemporaryDirectory() as temp_name:
            with (
                mock.patch(
                    "live_osquery_client.run_bounded_command",
                    side_effect=BoundedProcessError(
                        "command timed out after 60 seconds"
                    ),
                ),
                self.assertRaisesRegex(
                    LiveOsqueryClientError,
                    "transport failed",
                ) as raised,
            ):
                collect_live_osquery(
                    case_id="case-timeout",
                    requests=[{
                        "target_alias": "endpoint-a",
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "purpose": "verify endpoint",
                    }],
                    config=self.scheduled_config(temp_name),
                    persist=False,
                    approval_scope="scheduled_inventory",
                )

        self.assertEqual(raised.exception.reason_code, "broker_timeout")


    def test_collector_distinguishes_connect_failure_and_broker_rejection(self):
        with tempfile.TemporaryDirectory() as temp_name:
            config = self.scheduled_config(temp_name)
            for returncode, expected in ((255, "connect_failure"), (17, "broker_rejection")):
                completed = SimpleNamespace(
                    returncode=returncode,
                    stdout="",
                    stderr="restricted transport rejected the request",
                )
                with (
                    self.subTest(returncode=returncode),
                    mock.patch(
                        "live_osquery_client.run_bounded_command",
                        return_value=completed,
                    ),
                    self.assertRaises(LiveOsqueryClientError) as raised,
                ):
                    collect_live_osquery(
                        case_id="case-rejected",
                        requests=[{
                            "target_alias": "endpoint-a",
                            "query": "SELECT hostname FROM system_info LIMIT 1;",
                            "purpose": "verify endpoint",
                        }],
                        config=config,
                        persist=False,
                        approval_scope="scheduled_inventory",
                    )
                self.assertEqual(raised.exception.reason_code, expected)


    def test_collector_persists_immutable_batches_with_bounded_manifest(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        purpose = "verify endpoint identity"
        raw_artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-immutable",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    "target_alias": "endpoint-a",
                    "query": query,
                    "purpose": purpose,
                    "status": "ok",
                    "rows": [{"hostname": "endpoint-a"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 10,
                    "error": "",
                }
            ],
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_artifact),
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            config = {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
                "harness_operator_approval": {
                    "approved": True,
                    "target_aliases": ["endpoint-a"],
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                "relay_host": "relay.invalid",
                "relay_user": "broker",
                "identity_file": Path(temp_name) / "identity",
                "known_hosts": Path(temp_name) / "known_hosts",
                "connect_timeout_seconds": 5,
                "timeout_seconds": 30,
                "port": 22,
                "artifact_dir": artifact_dir,
                "max_saved_batches_per_case": 2,
            }
            with mock.patch(
                "live_osquery_client.run_bounded_command",
                return_value=completed,
            ):
                for _ in range(3):
                    collect_live_osquery(
                        case_id="case-immutable",
                        requests=[
                            {
                                "target_alias": "endpoint-a",
                                "query": query,
                                "purpose": purpose,
                            }
                        ],
                        config=config,
                        persist=True,
                    )
            case_dir = artifact_dir / "case-immutable"
            manifest = json.loads(
                (case_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["schema"],
                "onion-sentinel-live-osquery-manifest-v1",
            )
            self.assertEqual(manifest["retention_limit"], 2)
            self.assertEqual(len(manifest["entries"]), 2)
            artifact_files = sorted(
                path
                for path in case_dir.glob("*.json")
                if path.name != "manifest.json"
            )
            self.assertEqual(len(artifact_files), 2)
            self.assertTrue((case_dir / manifest["current"]).is_file())
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in [*artifact_files, case_dir / "manifest.json"]
                )
            )


    def test_concurrent_collectors_preserve_manifest_and_retention(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        purpose = "verify endpoint identity"
        raw_artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-concurrent",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    "target_alias": "endpoint-a",
                    "query": query,
                    "purpose": purpose,
                    "status": "ok",
                    "rows": [{"hostname": "endpoint-a"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 10,
                    "error": "",
                }
            ],
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_artifact),
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            config = {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
                "harness_operator_approval": {
                    "approved": True,
                    "target_aliases": ["endpoint-a"],
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                "relay_host": "relay.invalid",
                "relay_user": "broker",
                "identity_file": Path(temp_name) / "identity",
                "known_hosts": Path(temp_name) / "known_hosts",
                "connect_timeout_seconds": 5,
                "timeout_seconds": 30,
                "port": 22,
                "artifact_dir": artifact_dir,
                "max_saved_batches_per_case": 8,
            }

            def collect_one(_: int) -> dict[str, object]:
                return collect_live_osquery(
                    case_id="case-concurrent",
                    requests=[
                        {
                            "target_alias": "endpoint-a",
                            "query": query,
                            "purpose": purpose,
                        }
                    ],
                    config=config,
                    persist=True,
                )

            with mock.patch(
                "live_osquery_client.run_bounded_command",
                return_value=completed,
            ):
                with ThreadPoolExecutor(max_workers=12) as executor:
                    results = list(executor.map(collect_one, range(24)))

            self.assertEqual(len(results), 24)
            case_dir = artifact_dir / "case-concurrent"
            manifest = json.loads(
                (case_dir / "manifest.json").read_text(encoding="utf-8")
            )
            entries = manifest["entries"]
            self.assertEqual(len(entries), 8)
            self.assertEqual(
                len({entry["artifact"] for entry in entries}),
                len(entries),
            )
            artifact_files = {
                path.name
                for path in case_dir.glob("*.json")
                if path.name != "manifest.json"
            }
            self.assertEqual(
                artifact_files,
                {entry["artifact"] for entry in entries},
            )
            self.assertIn(manifest["current"], artifact_files)
            lock_path = case_dir / ".manifest.lock"
            lock_info = lock_path.lstat()
            self.assertTrue(stat.S_ISREG(lock_info.st_mode))
            self.assertEqual(lock_info.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(lock_info.st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(case_dir.stat().st_mode), 0o700)


    def test_persistence_rejects_unsafe_case_directory_and_lock(self):
        request_payload = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-lock",
            "requests": [],
        }
        artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-lock",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [],
        }
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            case_dir = artifact_dir / "case-lock"
            case_dir.mkdir(parents=True, mode=0o700)

            case_dir.chmod(0o755)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "case directory.*0700",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )

            case_dir.chmod(0o700)
            lock_path = case_dir / ".manifest.lock"
            lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o644)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "manifest lock.*0600",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )

            lock_path.unlink()
            target = case_dir / "not-a-lock"
            target.write_text("", encoding="utf-8")
            target.chmod(0o600)
            lock_path.symlink_to(target)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "manifest lock",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )
            self.assertFalse((case_dir / "manifest.json").exists())


