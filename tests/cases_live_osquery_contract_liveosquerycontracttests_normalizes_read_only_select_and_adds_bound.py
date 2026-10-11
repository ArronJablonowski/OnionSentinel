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

class LiveOsqueryContractTestsNormalizesReadOnlySelectAndAddsBoundCases:
    def test_normalizes_read_only_select_and_adds_bound(self):
        self.assertEqual(
            normalize_query(" SELECT pid, name FROM processes "),
            "SELECT pid, name FROM processes LIMIT 100;",
        )


    def test_rejects_joins_even_between_allowlisted_tables(self):
        with self.assertRaises(LiveOsqueryContractError):
            normalize_query(
                "SELECT p.pid, p.name, s.remote_address "
                "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid LIMIT 25;"
            )


    def test_rejects_mutations_comments_unknown_tables_and_excessive_limits(self):
        rejected = (
            "DELETE FROM processes;",
            "SELECT * FROM processes -- bypass",
            "SELECT * FROM socket_events;",
            "SELECT * FROM processes LIMIT 201;",
            "SELECT * FROM processes UNION SELECT * FROM users;",
            "WITH p AS (SELECT * FROM processes) SELECT * FROM p;",
            "SELECT * FROM processes, users;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)


    def test_rejects_quoted_tables_functions_and_projection_aliases(self):
        rejected = (
            'SELECT * FROM processes JOIN "shell_history" ON 1=1 LIMIT 1;',
            "SELECT * FROM processes JOIN `ssh_keys` ON 1=1 LIMIT 1;",
            "SELECT * FROM processes JOIN [file] ON 1=1 LIMIT 1;",
            "SELECT randomblob(1000000000) FROM processes LIMIT 1;",
            "SELECT zeroblob(1000000000) FROM processes LIMIT 1;",
            "SELECT printf('%1000000000s', name) FROM processes LIMIT 1;",
            'SELECT "8.8.8.8" AS "source.ip" FROM processes LIMIT 1;',
            "SELECT '8.8.8.8' AS source_ip FROM processes LIMIT 1;",
            "SELECT name AS source_ip FROM processes LIMIT 1;",
            "SELECT * FROM processes LIMIT 200, 1000000;",
            "SELECT * FROM processes LIMIT 1 + 1000000;",
            "SELECT * FROM processes LIMIT 10 OFFSET 1000000;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)


    def test_allows_single_table_native_columns_and_string_predicates(self):
        self.assertEqual(
            normalize_query(
                "SELECT pid, name, path FROM processes "
                "WHERE name = 'launchd' LIMIT 20"
            ),
            "SELECT pid, name, path FROM processes "
            "WHERE name = 'launchd' LIMIT 20;",
        )


    def test_rejects_wildcard_and_nonexistent_darwin_columns(self):
        for query in (
            "SELECT * FROM processes LIMIT 1;",
            "SELECT package_arch FROM homebrew_packages LIMIT 1;",
            "SELECT auto_updates FROM homebrew_packages LIMIT 1;",
            "SELECT app_name FROM homebrew_packages LIMIT 1;",
            "SELECT definitely_not_a_column FROM system_info LIMIT 1;",
            "SELECT pid FROM processes "
            "WHERE definitely_not_a_column = 'x' LIMIT 1;",
            "SELECT pid FROM processes "
            "ORDER BY definitely_not_a_column LIMIT 1;",
            "SELECT system_info.pid FROM processes LIMIT 1;",
        ):
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)


    def test_allows_mac_osquery_identity_and_version_probes(self):
        self.assertEqual(
            normalize_query(
                "SELECT version, build_platform FROM osquery_info LIMIT 1;"
            ),
            "SELECT version, build_platform FROM osquery_info LIMIT 1;",
        )
        self.assertEqual(
            normalize_query("SELECT version, build, arch FROM os_version LIMIT 1;"),
            "SELECT version, build, arch FROM os_version LIMIT 1;",
        )
        self.assertEqual(
            normalize_query(
                "SELECT name, path, version, type, prefix "
                "FROM homebrew_packages LIMIT 5;"
            ),
            "SELECT name, path, version, type, prefix "
            "FROM homebrew_packages LIMIT 5;",
        )


    def test_rejects_wildcard_or_unconfigured_endpoint_targets(self):
        for alias in ("*", "all", "unknown-endpoint"):
            with self.subTest(alias=alias):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_requests(
                        [
                            {
                                "target_alias": alias,
                                "query": "SELECT * FROM system_info;",
                                "purpose": "inventory",
                            }
                        ],
                        allowed_aliases=["workstation-01"],
                    )


    def test_binds_every_result_to_the_exact_submitted_request(self):
        requests = normalize_requests(
            [
                {
                    "target_alias": "workstation-01",
                    "query": "SELECT pid, name FROM processes LIMIT 10;",
                    "purpose": "correlate running processes",
                }
            ],
            allowed_aliases=["workstation-01"],
        )
        artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-1",
            "generated_at": "2026-07-23T00:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    **requests[0],
                    "status": "ok",
                    "rows": [{"pid": "42", "name": "launchd"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 50,
                    "error": "",
                }
            ],
        }
        normalized = validate_result_artifact(
            json.loads(json.dumps(artifact)),
            expected_requests=requests,
        )
        self.assertTrue(normalized["complete"])
        self.assertEqual(normalized["results"][0]["rows"][0]["pid"], "42")

        substituted = json.loads(json.dumps(artifact))
        substituted["results"][0]["target_alias"] = "workstation-02"
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(substituted, expected_requests=requests)

        missing = json.loads(json.dumps(artifact))
        missing["results"] = []
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(missing, expected_requests=requests)

        unexpected_column = json.loads(json.dumps(artifact))
        unexpected_column["results"][0]["rows"][0]["unexpected_secret"] = "value"
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query projection",
        ):
            validate_result_artifact(
                unexpected_column,
                expected_requests=requests,
            )

        missing_column = json.loads(json.dumps(artifact))
        missing_column["results"][0]["rows"][0].pop("name")
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query projection",
        ):
            validate_result_artifact(
                missing_column,
                expected_requests=requests,
            )

        impossible_count = json.loads(json.dumps(artifact))
        impossible_count["results"][0]["query"] = (
            "SELECT pid, name FROM processes LIMIT 1;"
        )
        impossible_count["results"][0]["total_rows"] = 2
        impossible_count["results"][0]["truncated"] = True
        requests_with_one_row_limit = normalize_requests(
            [
                {
                    "target_alias": "workstation-01",
                    "query": "SELECT pid, name FROM processes LIMIT 1;",
                    "purpose": "correlate running processes",
                }
            ],
            allowed_aliases=["workstation-01"],
        )
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query LIMIT",
        ):
            validate_result_artifact(
                impossible_count,
                expected_requests=requests_with_one_row_limit,
            )
