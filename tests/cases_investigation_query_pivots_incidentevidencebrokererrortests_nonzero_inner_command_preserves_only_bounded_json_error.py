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

class IncidentEvidenceBrokerErrorTestsNonzeroInnerCommandPreservesOnlyBoundedJsonErrorCases:
    def test_nonzero_inner_command_preserves_only_bounded_json_error(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout=json.dumps({
                "ok": False,
                "error": "positive control failed\nfor anchor",
                "detail": "query endpoint unavailable",
                "raw_hits": "MUST-NOT-BE-REFLECTED",
            }).encode("utf-8"),
            stderr=b"inner ssh warning\n",
        )

        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "incident-evidence.json"
            config_path.write_text(json.dumps({
                "host": "security-onion.invalid",
                "ssh_key": "/private/key",
                "known_hosts": "/private/known-hosts",
            }), encoding="utf-8")
            output = io.StringIO()
            fake_stdin = mock.Mock()
            fake_stdin.buffer = io.BytesIO(b"{}")
            with (
                mock.patch.dict(
                    self.broker.os.environ,
                    {
                        "ONION_SENTINEL_INCIDENT_EVIDENCE_CONFIG": str(config_path),
                        "SSH_ORIGINAL_COMMAND": "",
                    },
                    clear=False,
                ),
                mock.patch.object(self.broker.sys, "stdin", fake_stdin),
                mock.patch.object(
                    self.broker,
                    "run_bounded_command",
                    return_value=completed,
                ),
                contextlib.redirect_stdout(output),
            ):
                returncode = self.broker.main()

        response = json.loads(output.getvalue())
        self.assertEqual(returncode, 4)
        self.assertFalse(response["ok"])
        self.assertEqual(
            response["upstream_error"],
            "positive control failed for anchor",
        )
        self.assertEqual(response["upstream_detail"], "query endpoint unavailable")
        self.assertEqual(response["detail"], "inner ssh warning")
        self.assertNotIn("MUST-NOT-BE-REFLECTED", output.getvalue())


    def test_non_json_inner_stdout_is_not_reflected_and_stderr_is_sanitized(self) -> None:
        payload = self.broker._failed_command_payload(
            subprocess.CompletedProcess(
                args=[],
                returncode=255,
                stdout=b"arbitrary stdout MUST-NOT-BE-REFLECTED",
                stderr=b"\x1bConnection reset\n" + (b"x" * 2000),
            )
        )

        encoded = json.dumps(payload)
        self.assertNotIn("MUST-NOT-BE-REFLECTED", encoded)
        self.assertNotIn("\x1b", payload["detail"])
        self.assertNotIn("\n", payload["detail"])
        self.assertIn("Connection reset", payload["detail"])
        self.assertIn("[truncated]", payload["detail"])
        self.assertLessEqual(
            len(payload["detail"].encode("utf-8")),
            self.broker.MAX_ERROR_FIELD_BYTES,
        )
