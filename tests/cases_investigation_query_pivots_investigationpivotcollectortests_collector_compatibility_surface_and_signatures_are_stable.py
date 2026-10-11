from __future__ import annotations

from investigation_query_pivots_fixtures import (
    ALERT_INDEX_SCOPE,
    BIN_DIR,
    BROKER_PATH,
    COLLECTOR_PATH,
    COMPAT_V1_COLLECTOR_PATH,
    EVENT_TUPLE_FIELDS,
    EVENT_TUPLE_PATHS,
    INVESTIGATION_QUERY_CONTRACT,
    InvestigationQueryContractError,
    OBSERVABLE_FIELDS,
    PACKS,
    Path,
    QUERY_AUTHORIZATION,
    QUERY_RESPONSE,
    RELAY_APP_DIR,
    REPO_ROOT,
    WRAPPER_PATH,
    authorize_investigation_query_request,
    build_query_dsl,
    canonical_digest,
    context,
    contextlib,
    controls_for,
    copy,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    kql_equivalent,
    load_source_module,
    mock,
    oql_equivalent,
    proposal,
    query_endpoint,
    result_coverage,
    role_aware_context,
    role_aware_proposal,
    search_result_for,
    subprocess,
    sys,
    tempfile,
    unittest,
    valid_response,
    validate_investigation_query_response,
)

class InvestigationPivotCollectorTestsCollectorCompatibilitySurfaceAndSignaturesAreStableCases:
    def test_collector_compatibility_surface_and_signatures_are_stable(self) -> None:
        names = sorted(
            name for name in vars(self.collector)
            if not name.startswith("__")
        )
        self.assertEqual(len(names), 42)
        self.assertEqual(
            hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
            "068a954dd2a79bc5012e6e01a1515866441553f1c90b54dbc7f83bc4551eba85",
        )
        expected_signatures = {
            "_atomic_json": "(path: 'Path', payload: 'dict[str, Any]') -> 'None'",
            "_bounded_diagnostic_text": "(value: 'object', maximum_bytes: 'int') -> 'str'",
            "_compact_source": "(source: 'object') -> 'dict[str, Any]'",
            "_json_error_fields": "(raw: 'object') -> 'list[tuple[str, str]]'",
            "_model_evidence": "(response: 'dict[str, Any]') -> 'dict[str, Any]'",
            "_query_audit": "(response: 'dict[str, Any]') -> 'list[dict[str, Any]]'",
            "_read_json": "(path: 'Path', label: 'str') -> 'object'",
            "_transport": "(request: 'dict[str, Any]', config: 'dict[str, Any]') -> 'dict[str, Any]'",
            "_transport_failure_diagnostic": "(stdout: 'object', stderr: 'object') -> 'str'",
            "collect_investigation_pivots": (
                "(proposal: 'object', authorization_context: 'object', *, "
                "config_path: 'Path | str | dict[str, Any]' = "
                "PosixPath('/Users/aj_lobster/n8n-local/config/incident-evidence.json'), "
                "out_dir: 'Path | str' = "
                "PosixPath('/Users/aj_lobster/n8n-local/soc-alerts/investigation-pivots'), "
                "persist: 'bool' = True) -> 'dict[str, Any]'"
            ),
            "load_config": "(path: 'Path') -> 'dict[str, Any]'",
            "main": "() -> 'int'",
            "parse_args": "() -> 'argparse.Namespace'",
        }
        self.assertEqual(
            {
                name: str(inspect.signature(getattr(self.collector, name)))
                for name in expected_signatures
            },
            expected_signatures,
        )


    def test_collector_workflow_order_custody_and_persistence_are_stable(self) -> None:
        authorized_request = authorize_investigation_query_request(
            proposal(),
            context(),
        )
        response = valid_response(authorized_request)
        validated_response = validate_investigation_query_response(
            response,
            authorized_request,
        )
        original_model_evidence = self.collector._model_evidence
        original_query_audit = self.collector._query_audit
        original_atomic_json = self.collector._atomic_json
        calls = []

        def authorize(candidate, authorization):
            calls.append(("authorize", candidate, authorization))
            return authorized_request

        def load_config(path):
            calls.append(("load_config", path))
            return {"transport": "config"}

        def transport(request, config):
            calls.append(("transport", request, config))
            return response

        def validate(candidate, request):
            calls.append(("validate", candidate, request))
            return validated_response

        def model_evidence(candidate):
            calls.append(("model_evidence", candidate))
            return original_model_evidence(candidate)

        def query_audit(candidate):
            calls.append(("query_audit", candidate))
            return original_query_audit(candidate)

        def atomic_json(path, payload):
            calls.append(("atomic_json", path, payload))
            return original_atomic_json(path, payload)

        with tempfile.TemporaryDirectory() as temporary:
            out_dir = Path(temporary) / "pivots"
            config_path = Path(temporary) / "incident-evidence.json"
            with (
                mock.patch.object(
                    self.collector,
                    "authorize_investigation_query_request",
                    side_effect=authorize,
                ),
                mock.patch.object(
                    self.collector,
                    "load_config",
                    side_effect=load_config,
                ),
                mock.patch.object(
                    self.collector,
                    "_transport",
                    side_effect=transport,
                ),
                mock.patch.object(
                    self.collector,
                    "validate_investigation_query_response",
                    side_effect=validate,
                ),
                mock.patch.object(
                    self.collector,
                    "_model_evidence",
                    side_effect=model_evidence,
                ),
                mock.patch.object(
                    self.collector,
                    "_query_audit",
                    side_effect=query_audit,
                ),
                mock.patch.object(
                    self.collector,
                    "_atomic_json",
                    side_effect=atomic_json,
                ),
            ):
                artifact = self.collector.collect_investigation_pivots(
                    proposal(),
                    context(),
                    config_path=config_path,
                    out_dir=out_dir,
                )

            destination = (
                out_dir
                / authorized_request["authorization"]["case_id"]
                / f"{authorized_request['batch_id']}.json"
            )
            persisted = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

        self.assertEqual(
            [call[0] for call in calls],
            [
                "authorize", "load_config", "transport", "validate",
                "model_evidence", "query_audit", "atomic_json",
            ],
        )
        self.assertIs(calls[2][1], authorized_request)
        self.assertEqual(calls[2][2], {"transport": "config"})
        self.assertIs(calls[3][1], response)
        self.assertIs(calls[3][2], authorized_request)
        self.assertIs(calls[4][1], validated_response)
        self.assertIs(calls[5][1], validated_response)
        self.assertIs(calls[6][2], artifact)
        self.assertEqual(calls[6][1], destination)
        self.assertEqual(artifact["artifact_path"], str(destination))
        self.assertNotIn("artifact_path", persisted)
        self.assertEqual(artifact["audit"]["authorized_request"], authorized_request)
        self.assertEqual(
            artifact["audit"]["security_onion_response"],
            validated_response,
        )
        self.assertEqual(
            artifact["model_evidence"]["results"][0]["result_digest"],
            canonical_digest(validated_response["results"][0]),
        )
        self.assertEqual(
            artifact["query_audit"],
            artifact["audit"]["query_audit"],
        )


    def test_collector_transport_command_limits_and_request_bytes_are_stable(self) -> None:
        request = {"batch_id": "batch-1", "queries": [{"query_id": "query-1"}]}
        response = {"ok": True, "batch_id": "batch-1"}
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(response),
            stderr="",
        )
        config = {
            "host": "relay.invalid",
            "ssh_user": "forced-user",
            "ssh_key": "$ARR176_KEY_ROOT/id_ed25519",
            "known_hosts": "$ARR176_KEY_ROOT/known_hosts",
            "connect_timeout_seconds": "7",
            "timeout_seconds": "12.5",
            "max_response_bytes": self.collector.MAX_RESPONSE_BYTES + 1,
            "max_stderr_bytes": (256 * 1024) + 1,
        }
        with (
            mock.patch.dict(
                self.collector.os.environ,
                {"ARR176_KEY_ROOT": "/private/runtime"},
                clear=False,
            ),
            mock.patch.object(
                self.collector,
                "run_bounded_command",
                return_value=completed,
            ) as run,
        ):
            actual = self.collector._transport(request, config)

        self.assertEqual(actual, response)
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/ssh", "-T",
                "-o", "BatchMode=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=7",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=/private/runtime/known_hosts",
                "-i", "/private/runtime/id_ed25519",
                "forced-user@relay.invalid",
            ],
        )
        self.assertEqual(
            run.call_args.kwargs,
            {
                "stdin_text": json.dumps(
                    request,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                "timeout_seconds": 12.5,
                "max_stdout_bytes": self.collector.MAX_RESPONSE_BYTES,
                "max_stderr_bytes": 256 * 1024,
            },
        )


    def test_collector_returns_model_evidence_and_full_query_audit(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        with mock.patch.object(
            self.collector,
            "_transport",
            return_value=response,
        ):
            artifact = self.collector.collect_investigation_pivots(
                proposal(),
                context(),
                config_path={},
                persist=False,
            )

        self.assertTrue(artifact["complete"])
        model_result = artifact["model_evidence"]["results"][0]
        self.assertEqual(model_result["query_id"], "query-1")
        audit = artifact["query_audit"][0]
        self.assertEqual(audit["query_dsl"], build_query_dsl(request["queries"][0]))
        self.assertEqual(audit["index_scope"], PACKS["dns_activity"]["indices"])
        expected_result_digest = canonical_digest(response["results"][0])
        self.assertEqual(model_result["result_digest"], expected_result_digest)
        self.assertEqual(audit["result_digest"], expected_result_digest)
        self.assertEqual(
            artifact["audit"]["security_onion_response_digest"],
            canonical_digest(response),
        )
        compat_model_result = self.compat_v1_collector._model_evidence(
            response
        )["results"][0]
        compat_audit = self.compat_v1_collector._query_audit(response)[0]
        self.assertEqual(
            compat_model_result["result_digest"],
            expected_result_digest,
        )
        self.assertEqual(
            compat_audit["result_digest"],
            expected_result_digest,
        )


    def test_model_evidence_withholds_hits_when_controls_fail(self) -> None:
        request = authorize_investigation_query_request(proposal(), context())
        response = valid_response(request)
        response["complete"] = False
        response["partial"] = True
        response["controls"]["positive_anchor"]["passed"] = False
        response["semantic_validity"]["controls_valid"] = False
        response["semantic_validity"]["semantic_valid"] = False

        evidence = self.collector._model_evidence(response)

        self.assertFalse(evidence["controls_valid"])
        self.assertEqual(evidence["results"][0]["hits"], [])
        self.assertTrue(
            any(
                gap["query_id"] == "broker-controls"
                for gap in evidence["evidence_gaps"]
            )
        )


    def test_failed_transport_preserves_bounded_json_error_and_stderr(self) -> None:
        config = {
            "host": "relay.invalid",
            "ssh_user": "forced-user",
            "ssh_key": "/private/key",
            "known_hosts": "/private/known-hosts",
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=4,
            stdout=json.dumps({
                "ok": False,
                "error": "restricted broker failed\npositive control unavailable",
                "detail": "relay detail",
                "upstream_error": "Security Onion query timed out",
                "upstream_detail": "inner detail",
                "arbitrary_evidence": "MUST-NOT-BE-REFLECTED",
            }),
            stderr="Connection reset by peer\n",
        )

        for collector in (self.collector, self.compat_v1_collector):
            with self.subTest(contract=collector.INVESTIGATION_QUERY_CONTRACT):
                with mock.patch.object(
                    collector,
                    "run_bounded_command",
                    return_value=completed,
                ):
                    with self.assertRaises(
                        collector.InvestigationPivotClientError
                    ) as caught:
                        collector._transport({}, config)

                message = str(caught.exception)
                self.assertIn("restricted broker failed positive control unavailable", message)
                self.assertIn("Security Onion query timed out", message)
                self.assertIn("Connection reset by peer", message)
                self.assertNotIn("MUST-NOT-BE-REFLECTED", message)
                self.assertNotIn("\n", message)
                self.assertLessEqual(
                    len(
                        collector._transport_failure_diagnostic(
                            completed.stdout,
                            completed.stderr,
                        ).encode("utf-8")
                    ),
                    collector.MAX_TRANSPORT_DIAGNOSTIC_BYTES,
                )


    def test_failed_transport_does_not_reflect_non_json_stdout(self) -> None:
        config = {
            "host": "relay.invalid",
            "ssh_user": "forced-user",
            "ssh_key": "/private/key",
            "known_hosts": "/private/known-hosts",
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="arbitrary stdout MUST-NOT-BE-REFLECTED",
            stderr="\x1bConnection reset\n" + ("x" * 2000),
        )

        for collector in (self.collector, self.compat_v1_collector):
            with self.subTest(contract=collector.INVESTIGATION_QUERY_CONTRACT):
                with mock.patch.object(
                    collector,
                    "run_bounded_command",
                    return_value=completed,
                ):
                    with self.assertRaises(
                        collector.InvestigationPivotClientError
                    ) as caught:
                        collector._transport({}, config)

                message = str(caught.exception)
                self.assertIn("Connection reset", message)
                self.assertIn("[truncated]", message)
                self.assertNotIn("MUST-NOT-BE-REFLECTED", message)
                self.assertNotIn("\x1b", message)
                self.assertNotIn("\n", message)
