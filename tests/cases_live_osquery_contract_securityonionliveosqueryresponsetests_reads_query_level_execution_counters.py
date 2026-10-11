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

class SecurityOnionLiveOsqueryResponseTestsReadsQueryLevelExecutionCountersCases:
    def test_reads_query_level_execution_counters(self):
        state = self.wrapper._query_state(
            {
                "data": {
                    "action_id": "action-id",
                    "agents": ["agent-id"],
                    "status": "completed",
                    "queries": [
                        {
                            "action_id": "query-action-id",
                            "agents": ["agent-id"],
                            "query": "SELECT hostname FROM system_info LIMIT 1;",
                            "status": "completed",
                            "successful": 1,
                            "failed": 0,
                            "pending": 0,
                            "responded": 1,
                            "docs": 1,
                        }
                    ],
                }
            },
            expected_parent_action_id="action-id",
            expected_query_action_id="query-action-id",
            expected_agent_id="agent-id",
            expected_query="SELECT hostname FROM system_info LIMIT 1;",
        )
        self.assertEqual(state, ("completed", 1, 0, 0, 1, 1))


    def test_rejects_unbound_or_inconsistent_query_details(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        mutations = {
            "parent action": lambda value: value["data"].update(
                action_id="other-action"
            ),
            "parent agent": lambda value: value["data"].update(
                agents=["other-agent"]
            ),
            "multiple queries": lambda value: value["data"]["queries"].append(
                dict(value["data"]["queries"][0])
            ),
            "child action": lambda value: value["data"]["queries"][0].update(
                action_id="other-query-action"
            ),
            "child agent": lambda value: value["data"]["queries"][0].update(
                agents=["other-agent"]
            ),
            "sql": lambda value: value["data"]["queries"][0].update(
                query="SELECT * FROM processes LIMIT 1;"
            ),
            "unknown state": lambda value: value["data"]["queries"][0].update(
                status="expired"
            ),
            "boolean counter": lambda value: value["data"]["queries"][0].update(
                successful=True
            ),
            "negative counter": lambda value: value["data"]["queries"][0].update(
                docs=-1
            ),
            "counter mismatch": lambda value: value["data"]["queries"][0].update(
                responded=0
            ),
            "terminal pending": lambda value: value["data"]["queries"][0].update(
                pending=1
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(details))
                mutate(candidate)
                with self.assertRaises(self.wrapper.LiveQueryError):
                    self.wrapper._query_state(
                        candidate,
                        expected_parent_action_id="action-id",
                        expected_query_action_id="query-action-id",
                        expected_agent_id="agent-id",
                        expected_query=(
                            "SELECT hostname FROM system_info LIMIT 1;"
                        ),
                    )


    def test_rejects_parent_and_child_state_mismatch(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "running",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "completion state was inconsistent",
        ):
            self.wrapper._query_state(
                details,
                expected_parent_action_id="action-id",
                expected_query_action_id="query-action-id",
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )


    def test_rejects_inflight_details_with_missing_counters(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "running",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "running",
                    }
                ],
            }
        }
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "omitted the successful counter",
        ):
            self.wrapper._query_state(
                details,
                expected_parent_action_id="action-id",
                expected_query_action_id="query-action-id",
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )


    def test_waits_for_reported_result_documents_to_become_visible(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        # Pagination, index refresh, or authorization can expose a positive
        # hit total before any usable edge is returned. Total metadata alone
        # must not satisfy the result-visibility gate.
        empty_results = {"data": {"edges": [], "total": 1}}
        visible_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with (
            mock.patch.object(
                self.wrapper,
                "_http_json",
                side_effect=[
                    submitted,
                    details,
                    empty_results,
                    details,
                    visible_results,
                ],
            ) as http_json,
            mock.patch.object(self.wrapper.time, "sleep"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="result visibility test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 10,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [{"hostname": "endpoint-a"}])
        result_urls = [
            call.kwargs["url"]
            for call in http_json.call_args_list
            if "/results/" in call.kwargs["url"]
        ]
        self.assertTrue(result_urls)
        self.assertTrue(all("?page=0&pageSize=200" in url for url in result_urls))
        self.assertTrue(all("?page=1" not in url for url in result_urls))


    def test_waits_before_accepting_an_initial_zero_row_snapshot(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                    }
                ],
            }
        }

        def details(docs):
            return {
                "data": {
                    "action_id": "action-id",
                    "agents": ["agent-id"],
                    "status": "completed",
                    "queries": [
                        {
                            "action_id": "query-action-id",
                            "agents": ["agent-id"],
                            "query": query,
                            "status": "completed",
                            "successful": 1,
                            "failed": 0,
                            "pending": 0,
                            "responded": 1,
                            "docs": docs,
                        }
                    ],
                }
            }

        visible_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with (
            mock.patch.object(
                self.wrapper,
                "_http_json",
                side_effect=[
                    submitted,
                    details(0),
                    {"data": {"edges": [], "total": 0}},
                    details(1),
                    visible_results,
                ],
            ),
            mock.patch.object(self.wrapper.time, "sleep"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query=query,
                purpose="zero snapshot visibility test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 10,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [{"hostname": "endpoint-a"}])


    def test_missing_reported_result_documents_fails_closed(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, {"data": {"edges": [], "total": 1}}],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="missing result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("did not match readable rows", result["error"])


    def test_partial_reported_result_documents_fail_closed(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 2;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 2;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 2,
                    }
                ],
            }
        }
        partial_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 2,
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, partial_results],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 2;",
                purpose="partial result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 2)
        self.assertIn("did not match readable rows", result["error"])


    def test_successful_zero_row_query_is_complete_evidence(self):
        query = "SELECT hostname FROM system_info WHERE hostname = 'absent' LIMIT 1;"
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 0,
                    }
                ],
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, {"data": {"edges": [], "total": 0}}],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query=query,
                purpose="zero result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 0)
        self.assertFalse(result["truncated"])


    def test_reads_current_elastic_result_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {
                            "_id": "result-1",
                            "_source": {
                                "agent": {"id": "agent-id"},
                                "action_id": "query-action-id",
                                "osquery": {"pid": "42", "name": "launchd"},
                            }
                        }
                    ],
                    "total": 1,
                }
            },
            expected_agent_id="agent-id",
            expected_action_id="query-action-id",
        )
        self.assertEqual(rows, [{"pid": "42", "name": "launchd"}])
        self.assertEqual(total, 1)


    def test_accepts_legacy_nested_columns_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {
                            "_id": "result-1",
                            "_source": {
                                "agent": {"id": "agent-id"},
                                "action_id": "query-action-id",
                                "osquery": {"columns": {"uid": "501"}},
                            }
                        }
                    ],
                    "total": {"value": 1, "relation": "eq"},
                }
            },
            expected_agent_id="agent-id",
            expected_action_id="query-action-id",
        )
        self.assertEqual(rows, [{"uid": "501"}])
        self.assertEqual(total, 1)


    def test_rejects_invalid_or_impossible_result_totals(self):
        edge = {
            "_id": "result-1",
            "_source": {
                "agent": {"id": "agent-id"},
                "action_id": "query-action-id",
                "osquery": {"pid": "42"},
            }
        }
        invalid_totals = (None, True, "1", -1, 201)
        for total in invalid_totals:
            with (
                self.subTest(total=total),
                self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "total was invalid",
                ),
            ):
                self.wrapper._result_rows(
                    {"data": {"edges": [edge], "total": total}},
                    expected_agent_id="agent-id",
                    expected_action_id="query-action-id",
                )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "smaller than its readable rows",
        ):
            self.wrapper._result_rows(
                {"data": {"edges": [edge], "total": 0}},
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "total was inexact",
        ):
            self.wrapper._result_rows(
                {
                    "data": {
                        "edges": [edge],
                        "total": {"value": 1, "relation": "gte"},
                    }
                },
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "total was inexact",
        ):
            self.wrapper._result_rows(
                {
                    "data": {
                        "edges": [edge],
                        "total": {"value": 1},
                    }
                },
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )


    def test_rejects_missing_or_duplicate_result_edge_identities(self):
        edge = {
            "_id": "result-1",
            "_source": {
                "agent": {"id": "agent-id"},
                "action_id": "query-action-id",
                "osquery": {"pid": "42"},
            },
        }
        for edges in (
            [{key: value for key, value in edge.items() if key != "_id"}],
            [edge, dict(edge)],
        ):
            with self.assertRaisesRegex(
                self.wrapper.LiveQueryError,
                "invalid or duplicate identity",
            ):
                self.wrapper._result_rows(
                    {"data": {"edges": edges, "total": len(edges)}},
                    expected_agent_id="agent-id",
                    expected_action_id="query-action-id",
                )


    def test_rejects_result_rows_from_a_different_agent_or_action(self):
        response = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "other-agent"},
                            "action_id": "query-action-id",
                            "osquery": {"pid": "42"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "target agent"):
            self.wrapper._result_rows(
                response,
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )

        response["data"]["edges"][0]["_source"]["agent"]["id"] = "agent-id"
        response["data"]["edges"][0]["_source"]["action_id"] = "other-action"
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "query action"):
            self.wrapper._result_rows(
                response,
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )


    def test_submission_identity_is_exact(self):
        response = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        self.assertEqual(
            self.wrapper._extract_action_ids(
                response,
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            ),
            ("action-id", "query-action-id"),
        )
        response["data"]["agents"] = ["other-agent"]
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "exact target"):
            self.wrapper._extract_action_ids(
                response,
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )


