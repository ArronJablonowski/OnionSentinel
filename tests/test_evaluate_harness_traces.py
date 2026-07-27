import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVALUATOR_PATH = ROOT / "operations" / "evaluate-harness-traces.py"
HARNESS_PATH = ROOT / "n8n" / "bin" / "onion_sentinel_harness.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
SPEC = importlib.util.spec_from_file_location(
    "harness_trace_evaluator",
    EVALUATOR_PATH,
)
evaluator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(evaluator)

HARNESS_SPEC = importlib.util.spec_from_file_location(
    "evaluator_test_harness_module",
    HARNESS_PATH,
)
harness = importlib.util.module_from_spec(HARNESS_SPEC)
assert HARNESS_SPEC and HARNESS_SPEC.loader
sys.modules[HARNESS_SPEC.name] = harness
HARNESS_SPEC.loader.exec_module(harness)


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def digest_json(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def create_trace_database(path: Path) -> None:
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE harness_runs (
                run_id TEXT PRIMARY KEY,
                trace_id TEXT,
                case_id TEXT,
                role TEXT,
                task_kind TEXT,
                status TEXT,
                stage TEXT,
                policy_mode TEXT,
                started_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE harness_events (
                run_id TEXT,
                sequence INTEGER,
                event_id TEXT,
                idempotency_key TEXT,
                event_type TEXT,
                stage TEXT,
                created_at TEXT,
                payload_json TEXT,
                payload_sha256 TEXT,
                previous_event_sha256 TEXT,
                event_sha256 TEXT
            );
            CREATE TABLE harness_evidence (
                run_id TEXT,
                evidence_ref TEXT,
                source_class TEXT,
                trust_tier TEXT,
                corroborating INTEGER
            );
            CREATE TABLE harness_hypotheses (
                run_id TEXT,
                hypothesis_id TEXT,
                status TEXT
            );
            CREATE TABLE harness_decisions (
                run_id TEXT,
                decision_id TEXT,
                decision_type TEXT,
                payload_json TEXT,
                created_at TEXT
            );
            CREATE TABLE harness_model_calls (
                run_id TEXT,
                call_id TEXT,
                purpose TEXT,
                requested_route TEXT,
                observed_model TEXT,
                observed_provider TEXT,
                independent_review INTEGER,
                status TEXT,
                duration_ms INTEGER,
                created_at TEXT
            );
            CREATE TABLE harness_tool_calls (
                run_id TEXT,
                call_id TEXT,
                round_number INTEGER,
                backend TEXT,
                capability TEXT,
                status TEXT,
                read_only INTEGER,
                coverage TEXT,
                truncated INTEGER
            );
            """
        )
        connection.execute(
            """
            INSERT INTO harness_runs(
                run_id, trace_id, case_id, role, task_kind, status, stage,
                policy_mode, started_at, completed_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "run-1",
                "trace-1",
                "case-1",
                "incident-responder",
                "incident-response",
                "succeeded",
                "complete",
                "shadow",
                "2026-07-25T00:00:00Z",
                "2026-07-25T00:01:00Z",
            ),
        )

        previous = "0" * 64
        event_values = [
            ("run.started", "intake", {}, "run.started"),
            (
                "policy.budget",
                "query-planning",
                {
                    "operation": "query batch",
                    "observed": {"round": 1, "request_count": 3},
                    "violations": [
                        "max_queries_total",
                        "max_queries_per_round",
                    ],
                    "policy_mode": "shadow",
                },
                "policy.budget:query-round:1",
            ),
            (
                "queries.completed",
                "query-execution",
                {
                    "round": 1,
                    "budget_violations": [
                        "max_queries_total",
                        "max_queries_per_round",
                    ],
                },
                "queries.completed:1",
            ),
            (
                "policy.budget",
                "primary-analysis",
                {
                    "operation": "model call",
                    "observed": {
                        "call_id": "primary-call",
                        "prompt_bytes": 2_000_000,
                    },
                    "violations": ["max_prompt_evidence_bytes"],
                    "policy_mode": "shadow",
                },
                "policy.budget:model:primary-call",
            ),
            (
                "policy.memory-promotion",
                "post-processing",
                {
                    "allowed": False,
                    "requires_approval": True,
                    "candidate_count": 2,
                    "reason": "shared memory requires explicit human approval",
                },
                "policy.memory-promotion",
            ),
            (
                "run.succeeded",
                "complete",
                {},
                "run.terminal:succeeded",
            ),
        ]
        for sequence, (event_type, stage, payload, idempotency_key) in enumerate(
            event_values, start=1
        ):
            payload_json = canonical_json(payload)
            payload_sha256 = hashlib.sha256(
                payload_json.encode("utf-8")
            ).hexdigest()
            body = {
                "run_id": "run-1",
                "sequence": sequence,
                "idempotency_key": idempotency_key,
                "event_type": event_type,
                "stage": stage,
                "created_at": f"2026-07-25T00:00:0{sequence}Z",
                "payload_sha256": payload_sha256,
                "previous_event_sha256": previous,
            }
            event_sha256 = digest_json(body)
            connection.execute(
                """
                INSERT INTO harness_events(
                    run_id, sequence, event_id, idempotency_key, event_type,
                    stage, created_at, payload_json, payload_sha256,
                    previous_event_sha256, event_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "run-1",
                    sequence,
                    f"evt-{event_sha256[:32]}",
                    idempotency_key,
                    event_type,
                    stage,
                    body["created_at"],
                    payload_json,
                    payload_sha256,
                    previous,
                    event_sha256,
                ),
            )
            previous = event_sha256

        connection.executemany(
            """
            INSERT INTO harness_evidence(
                run_id, evidence_ref, source_class, trust_tier, corroborating
            ) VALUES(?, ?, ?, ?, ?)
            """,
            [
                (
                    "run-1",
                    "alert:one",
                    "suricata_alert",
                    "trusted-collector",
                    1,
                ),
                (
                    "run-1",
                    "query:one",
                    "security_onion_investigation_query",
                    "read-only-backend",
                    1,
                ),
            ],
        )
        connection.execute(
            """
            INSERT INTO harness_hypotheses(run_id, hypothesis_id, status)
            VALUES('run-1', 'hypothesis-1', 'unresolved')
            """
        )
        connection.executemany(
            """
            INSERT INTO harness_decisions(
                run_id, decision_id, decision_type, payload_json, created_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            [
                (
                    "run-1",
                    "primary",
                    "primary-analysis",
                    canonical_json(
                        {
                            "detection_outcome": "true_positive_malicious",
                            "handling": "contain",
                        }
                    ),
                    "2026-07-25T00:00:20Z",
                ),
                (
                    "run-1",
                    "independent-review",
                    "independent-review",
                    canonical_json(
                        {
                            "detection_outcome": "inconclusive",
                            "handling": "investigate",
                        }
                    ),
                    "2026-07-25T00:00:30Z",
                ),
                (
                    "run-1",
                    "final",
                    "post-review-analysis",
                    canonical_json(
                        {
                            # Deliberately matches the reviewer. The evaluator
                            # must still compare primary vs independent-review,
                            # not the reconciled final decision.
                            "detection_outcome": "inconclusive",
                            "handling": "investigate",
                        }
                    ),
                    "2026-07-25T00:00:40Z",
                ),
            ],
        )
        connection.executemany(
            """
            INSERT INTO harness_model_calls(
                run_id, call_id, purpose, requested_route, observed_model,
                observed_provider, independent_review, status, duration_ms,
                created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "run-1",
                    "primary-call",
                    "primary-analysis",
                    "codex:gpt-5.6-terra",
                    "gpt-5.6-terra",
                    "codex-cli",
                    0,
                    "completed",
                    1000,
                    "2026-07-25T00:00:10Z",
                ),
                (
                    "run-1",
                    "review-call",
                    "independent-review",
                    "codex:gpt-5.6-sol",
                    "gpt-5.6-sol",
                    "codex-cli",
                    1,
                    "completed",
                    2000,
                    "2026-07-25T00:00:25Z",
                ),
            ],
        )
        connection.executemany(
            """
            INSERT INTO harness_tool_calls(
                run_id, call_id, round_number, backend, capability, status,
                read_only, coverage, truncated
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "run-1",
                    "elastic-ok",
                    1,
                    "elastic",
                    "security-onion.events.query",
                    "ok",
                    1,
                    "exact-zero",
                    0,
                ),
                (
                    "run-1",
                    "osquery-rejected",
                    1,
                    "osquery",
                    "endpoint.osquery.query",
                    "rejected",
                    1,
                    "evidence-gap",
                    1,
                ),
                (
                    "run-1",
                    "unsafe-tool",
                    1,
                    "unknown",
                    "unknown",
                    "ok",
                    0,
                    "bounded-result",
                    0,
                ),
            ],
        )
        connection.commit()


def create_terminal_harness_database(path: Path) -> str:
    prompt = {
        "alert": {
            "alert_id": "alert-ledger-1",
            "rule_name": "Terminal ledger evaluator fixture",
        },
        "evidence_reference_contract": {
            "schema": "onion-sentinel-evidence-reference-contract-v1",
            "references": [
                {
                    "ref": "alert:ledger-1",
                    "source": "security-onion-alert",
                    "source_class": "suricata_alert",
                    "status": "available",
                    "returned": 1,
                    "corroborating": True,
                }
            ],
        },
    }
    policy = harness.HarnessPolicy.from_dict(
        {
            "schema": harness.POLICY_SCHEMA,
            "version": "1.0.0",
            "enabled": True,
            "mode": "enforce",
            "budgets": dict(harness.DEFAULT_BUDGETS),
            "role_capabilities": {
                role: sorted(capabilities)
                for role, capabilities in harness.DEFAULT_ROLE_CAPABILITIES.items()
            },
            "approval_required": [],
            "memory": {
                "require_independent_agreement": True,
                "shared_requires_human_approval": True,
            },
        }
    )
    envelope = harness.JobEnvelope.from_prompt(
        run_id="terminal-ledger-run",
        prompt_package=prompt,
        role=harness.AgentRole.INCIDENT_RESPONDER.value,
        assigned_route="codex-cli:gpt-5.6-sol:high",
        configuration={"query_mode": "read-only"},
    )
    run = harness.HarnessRun(
        harness.HarnessStore(path),
        envelope,
        policy,
    )
    run.catalogue_prompt_evidence(prompt)
    run.complete()
    return run.run_id


def replace_terminal_manifest(
    database: Path,
    run_id: str,
    manifest: dict | None,
    *,
    legacy_identity: bool = False,
) -> None:
    """Rewrite terminal metadata while preserving the event hash chain."""
    with harness._connect(database) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM harness_events
            WHERE run_id = ?
            ORDER BY sequence
            """,
            (run_id,),
        ).fetchall()
        previous = "0" * 64
        for row in rows:
            payload = json.loads(row["payload_json"])
            if legacy_identity and row["event_type"] == "run.started":
                payload.pop("assigned_reviewer_route", None)
            if row["event_type"] == "run.succeeded":
                if manifest is None:
                    payload.pop("ledger_manifest", None)
                else:
                    payload["ledger_manifest"] = manifest
            payload_json = harness.canonical_json(payload)
            payload_sha256 = hashlib.sha256(
                payload_json.encode("utf-8")
            ).hexdigest()
            body = {
                "run_id": run_id,
                "sequence": int(row["sequence"]),
                "idempotency_key": row["idempotency_key"],
                "event_type": row["event_type"],
                "stage": row["stage"],
                "created_at": row["created_at"],
                "payload_sha256": payload_sha256,
                "previous_event_sha256": previous,
            }
            event_sha256 = harness.digest_json(body)
            connection.execute(
                """
                UPDATE harness_events
                SET payload_json = ?, payload_sha256 = ?,
                    previous_event_sha256 = ?,
                    event_sha256 = ?, event_id = ?
                WHERE run_id = ? AND sequence = ?
                """,
                (
                    payload_json,
                    payload_sha256,
                    previous,
                    event_sha256,
                    f"evt-{event_sha256[:32]}",
                    run_id,
                    row["sequence"],
                ),
            )
            previous = event_sha256


class HarnessTraceEvaluatorTests(unittest.TestCase):
    def test_reports_requested_metrics_and_leaves_database_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_trace_database(database)
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            report = evaluator.evaluate_database(database)

            self.assertEqual(report["run_count"], 1)
            self.assertEqual(report["completion"]["success_rate"], 1.0)
            self.assertTrue(report["integrity"]["all_chains_valid"])
            self.assertEqual(report["models"]["call_count"], 2)
            self.assertEqual(report["models"]["independent_review_call_count"], 1)
            self.assertEqual(report["tools"]["call_count"], 3)
            self.assertEqual(report["tools"]["rejected_count"], 1)
            self.assertEqual(report["tools"]["coverage_gap_count"], 1)
            self.assertEqual(report["tools"]["truncated_count"], 1)
            self.assertEqual(report["tools"]["read_only_violation_count"], 1)
            self.assertEqual(
                report["evidence"]["average_distinct_source_classes_per_run"],
                2.0,
            )
            self.assertEqual(
                report["reviewer"]["material_disagreement_runs"],
                1,
            )
            self.assertEqual(
                report["runs"][0]["reviewer"]["disputed_fields"],
                ["detection_outcome", "handling"],
            )
            self.assertEqual(
                report["runs"][0]["reviewer"]["comparison_basis"],
                "primary_vs_independent-review",
            )
            self.assertEqual(report["budgets"]["violation_runs"], 1)
            self.assertEqual(
                report["budgets"]["violation_counts"],
                {
                    "max_prompt_evidence_bytes": 1,
                    "max_queries_per_round": 1,
                    "max_queries_total": 1,
                },
            )
            self.assertEqual(report["budgets"]["violation_operation_count"], 3)
            query_operations = [
                item
                for item in report["runs"][0]["budget_violation_operations"]
                if item["operation_id"] == "query-round:1"
            ]
            self.assertEqual(len(query_operations), 2)
            self.assertTrue(
                all(
                    item["sources"]
                    == ["policy.budget", "queries.completed"]
                    for item in query_operations
                )
            )
            self.assertEqual(report["memory_promotion"]["blocked_count"], 1)
            self.assertEqual(
                report["memory_promotion"]["requires_approval_count"],
                1,
            )
            self.assertEqual(report["memory_promotion"]["candidate_count"], 2)
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)

    def test_run_filter_unknown_run_and_private_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "harness.sqlite3"
            output = root / "reports" / "evaluation.json"
            create_trace_database(database)

            report = evaluator.evaluate_database(database, "run-1")
            evaluator.atomic_private_json(output, report)

            self.assertEqual(report["selected_run_id"], "run-1")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["schema"],
                evaluator.REPORT_SCHEMA,
            )
            with self.assertRaisesRegex(evaluator.EvaluationError, "unknown"):
                evaluator.evaluate_database(database, "run-missing")

    def test_detects_tampered_chain_and_optional_failure_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_trace_database(database)
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_events SET payload_json = '{"tampered":true}'
                    WHERE run_id = 'run-1' AND sequence = 2
                    """
                )
                connection.commit()

            report = evaluator.evaluate_database(database)

            self.assertFalse(report["integrity"]["all_chains_valid"])
            self.assertEqual(report["integrity"]["invalid_run_ids"], ["run-1"])
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = evaluator.main(
                    [
                        "--db",
                        str(database),
                        "--fail-on-invalid-chain",
                    ]
                )
            self.assertEqual(exit_code, 1)

    def test_read_only_evaluator_detects_terminal_ledger_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            report = evaluator.evaluate_database(database, run_id)
            self.assertTrue(report["integrity"]["all_chains_valid"])
            self.assertTrue(
                report["runs"][0]["integrity"]["ledger_manifest_bound"]
            )

            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_evidence
                    SET status = 'tampered-after-completion'
                    WHERE run_id = ? AND evidence_ref = 'alert:ledger-1'
                    """,
                    (run_id,),
                )
                connection.commit()
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            report = evaluator.evaluate_database(database, run_id)

            self.assertFalse(report["integrity"]["all_chains_valid"])
            self.assertEqual(report["integrity"]["invalid_run_ids"], [run_id])
            self.assertIn(
                "terminal ledger manifest mismatch",
                report["runs"][0]["integrity"]["errors"],
            )
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)

    def test_current_terminal_manifest_is_mandatory_and_v1_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            with harness._connect(database) as connection:
                legacy_manifest = harness.ledger_manifest(
                    connection,
                    run_id,
                    schema=harness.LEDGER_MANIFEST_SCHEMA_V1,
                )
            replace_terminal_manifest(
                database,
                run_id,
                legacy_manifest,
                legacy_identity=True,
            )
            report = evaluator.evaluate_database(database, run_id)
            integrity = report["runs"][0]["integrity"]
            self.assertTrue(integrity["valid"])
            self.assertTrue(integrity["ledger_manifest_required"])
            self.assertEqual(
                integrity["ledger_manifest_schema"],
                evaluator.LEDGER_MANIFEST_SCHEMA_V1,
            )

            replace_terminal_manifest(database, run_id, None)
            report = evaluator.evaluate_database(database, run_id)
            integrity = report["runs"][0]["integrity"]
            self.assertFalse(integrity["valid"])
            self.assertFalse(integrity["ledger_manifest_bound"])
            self.assertIn(
                "terminal ledger manifest is missing or malformed",
                integrity["errors"],
            )

    def test_rejects_future_database_schema_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_terminal_harness_database(database)
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_metadata
                    SET value = ?
                    WHERE key = 'schema_version'
                    """,
                    (str(evaluator.CURRENT_SQL_SCHEMA_VERSION + 1),),
                )
                connection.commit()
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            with self.assertRaisesRegex(
                evaluator.EvaluationError,
                "newer runtime",
            ):
                evaluator.evaluate_database(database)

            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)

    def test_reports_route_authorization_and_observed_identity_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "route-audit-test",
                    "enabled": True,
                    "mode": "shadow",
                    "budgets": dict(harness.DEFAULT_BUDGETS),
                    "role_capabilities": {
                        role: sorted(capabilities)
                        for role, capabilities
                        in harness.DEFAULT_ROLE_CAPABILITIES.items()
                    },
                    "approval_required": [],
                    "memory": {
                        "require_independent_agreement": True,
                        "shared_requires_human_approval": True,
                    },
                }
            )
            prompt = {
                "alert": {"alert_id": "route-audit-alert"},
                "evidence_reference_contract": {"references": []},
            }
            route = "codex-cli:gpt-5.6-sol:high"
            envelope = harness.JobEnvelope.from_prompt(
                run_id="route-audit-run",
                prompt_package=prompt,
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-terra:high"
                },
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            run.preflight_model_call(
                call_id="authorized-wrong-runtime",
                input_value={"case": "route-audit"},
                requested_route=route,
                purpose="authorized model call",
            )
            run.model_call(
                call_id="authorized-wrong-runtime",
                purpose="authorized model call",
                requested_route=route,
                response={
                    "_analysis_model": "gemma4:31b",
                    "_analysis_model_path": "ollama",
                    "_analysis_provider": "ollama",
                    "_analysis_model_route": "ollama:gemma4:31b",
                },
                input_value={"case": "route-audit"},
                duration_seconds=0.1,
            )
            run.model_call(
                call_id="missing-authorization",
                purpose="direct model call",
                requested_route=route,
                response={
                    "_analysis_model": "gpt-5.6-sol",
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_provider": "codex-cli",
                    "_analysis_model_route": route,
                },
                input_value={"case": "route-audit"},
                duration_seconds=0.1,
            )
            run.complete(check_budget=False)

            report = evaluator.evaluate_database(database, run.run_id)
            route_metrics = report["runs"][0]["models"][
                "route_consistency"
            ]
            self.assertEqual(route_metrics["authorized_call_count"], 1)
            self.assertEqual(
                route_metrics["authorization_failure_count"],
                1,
            )
            self.assertEqual(
                route_metrics["authorization_failures"][0]["call_id"],
                "missing-authorization",
            )
            self.assertIn(
                "authorization-event-missing",
                route_metrics["authorization_failures"][0]["reasons"],
            )
            self.assertEqual(route_metrics["identity_mismatch_count"], 1)
            self.assertEqual(
                route_metrics["identity_failures"][0]["call_id"],
                "authorized-wrong-runtime",
            )
            self.assertEqual(
                report["models"]["route_authorization"]["failure_count"],
                1,
            )
            self.assertEqual(
                report["models"]["runtime_identity"]["mismatch_count"],
                1,
            )
            self.assertIn(
                "model-route-authorization-failure",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertIn(
                "model-runtime-identity-mismatch",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertTrue(report["runs"][0]["integrity"]["valid"])

    def test_installer_preserves_policy_and_installs_harness_assets(self):
        source = INSTALLER_PATH.read_text(encoding="utf-8")
        policy = '$STACK_DIR/config/investigation_harness_policy.json'
        policy_guard = f'if [[ ! -f "{policy}" ]]'
        policy_copy = (
            'cp "$REPO_DIR/n8n/config/investigation_harness_policy.json" \\\n'
            f'    "{policy}"'
        )
        self.assertIn(policy_guard, source)
        self.assertIn(policy_copy, source)
        self.assertLess(source.index(policy_guard), source.index(policy_copy))
        self.assertIn(f'chmod 0600 "{policy}"', source)
        self.assertIn(
            "policy must be a regular file",
            source,
        )
        self.assertIn(
            "policy schema must be a regular file",
            source,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/config/investigation_harness_policy.schema.json"',
            source,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/onion_sentinel_harness.py"',
            source,
        )
        self.assertIn(
            (
                'cp "$REPO_DIR/operations/evaluate-harness-traces.py" '
                '"$STACK_DIR/bin/evaluate-harness-traces.py"'
            ),
            source,
        )


if __name__ == "__main__":
    unittest.main()
