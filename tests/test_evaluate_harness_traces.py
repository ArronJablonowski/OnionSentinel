from __future__ import annotations

import contextlib
import collections
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
                    "primary-initial",
                    evaluator.PRIMARY_INITIAL_PURPOSE,
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
                    "independent-review-1",
                    evaluator.REVIEWER_REPAIR_PURPOSE,
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


def create_terminal_harness_database(
    path: Path,
    *,
    skill_registry_version: int = 1,
) -> str:
    prompt = {
        "alert": {
            "alert_id": "alert-ledger-1",
            "rule_name": "Terminal ledger evaluator fixture",
        },
        "investigation_skills": {
            "schema": "onion-sentinel-investigation-skill-selection-v1",
            "mode": "shadow",
            "registry_version": skill_registry_version,
            "registry_sha256": "a" * 64,
            "selected": (
                [
                    {
                        "id": "suricata-detection-validation",
                        "version": 3,
                        "skill_sha256": "b" * 64,
                        "evidence_requirements": [
                            "This skill content must not enter the trace."
                        ],
                    }
                ]
                if skill_registry_version > 0
                else []
            ),
            "selected_count": 1 if skill_registry_version > 0 else 0,
            "truncated": False,
            "enforcement": "advisory_only",
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
    def test_resolved_repair_is_not_reported_as_tool_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
            {
                "call_id": "round-2-exact-ssh",
                "round_number": 2,
                "status": "ok",
                "coverage": "exact-zero",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            [],
        )

    def test_unrepaired_tool_failure_remains_a_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            ["round-1-exact-ssh"],
        )

    def test_terminal_repair_failure_remains_a_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
            {
                "call_id": "round-2-exact-ssh",
                "round_number": 2,
                "status": "error",
                "coverage": "evidence-gap",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            ["round-2-exact-ssh"],
        )

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
            legacy_skill = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertTrue(legacy_skill["legacy"])
            self.assertTrue(legacy_skill["valid"])
            self.assertFalse(legacy_skill["mandatory_ready"])
            self.assertEqual(
                report["skill_selection_attestation"]["legacy_run_count"],
                1,
            )
            self.assertEqual(report["models"]["call_count"], 2)
            self.assertEqual(report["models"]["independent_review_call_count"], 1)
            self.assertEqual(report["models"]["purpose_count"], 2)
            self.assertEqual(
                report["models"]["terminally_successful_purpose_count"],
                2,
            )
            self.assertEqual(report["models"]["incomplete_purpose_count"], 0)
            self.assertEqual(
                report["models"]["malformed_purpose_sequence_count"],
                0,
            )
            model_contract = report["runs"][0]["models"][
                "model_call_contract"
            ]
            self.assertTrue(model_contract["valid"])
            self.assertEqual(
                model_contract["canonical_model_call_count"],
                2,
            )
            self.assertEqual(
                model_contract["facts_sha256"],
                evaluator.digest_json(model_contract["facts"]),
            )
            self.assertEqual(report["tools"]["call_count"], 3)
            self.assertEqual(report["tools"]["successful_call_count"], 2)
            self.assertEqual(report["tools"]["read_only_call_count"], 2)
            self.assertEqual(report["tools"]["rejected_count"], 1)
            self.assertEqual(report["tools"]["coverage_gap_count"], 1)
            self.assertEqual(report["tools"]["truncated_count"], 1)
            self.assertEqual(report["tools"]["read_only_violation_count"], 1)
            self.assertEqual(
                report["runs"][0]["tools"]["successful_call_count"],
                2,
            )
            self.assertEqual(
                report["runs"][0]["tools"]["read_only_call_count"],
                2,
            )
            bindings = report["runs"][0]["tools"][
                "successful_read_only_call_bindings"
            ]
            self.assertEqual(len(bindings), 1)
            self.assertEqual(bindings[0]["call_id"], "elastic-ok")
            self.assertIs(bindings[0]["read_only"], True)
            self.assertEqual(
                report["runs"][0]["tools"][
                    "successful_read_only_call_bindings_sha256"
                ],
                evaluator.digest_json(bindings),
            )
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

    def test_validates_digest_bound_sanitized_skill_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertEqual(
                attestation,
                {
                    "present": True,
                    "legacy": False,
                    "valid": True,
                    "available": True,
                    "job_digest_bound": True,
                    "mandatory_ready": True,
                    "registry_version": 1,
                    "registry_sha256": "a" * 64,
                    "selected": [
                        {
                            "id": "suricata-detection-validation",
                            "version": 3,
                            "skill_sha256": "b" * 64,
                        }
                    ],
                    "selected_count": 1,
                    "truncated": False,
                    "advisory_mode": "advisory_only",
                    "error_count": 0,
                    "errors": [],
                },
            )
            self.assertEqual(
                report["skill_selection_attestation"],
                {
                    "present_run_count": 1,
                    "valid_run_count": 1,
                    "mandatory_ready_run_count": 1,
                    "legacy_run_count": 0,
                    "unavailable_run_count": 0,
                    "invalid_run_count": 0,
                    "invalid_run_ids": [],
                },
            )
            serialized = json.dumps(report, sort_keys=True)
            self.assertNotIn(
                "This skill content must not enter the trace",
                serialized,
            )

    def test_version_zero_skill_registry_is_never_evaluation_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(
                database,
                skill_registry_version=0,
            )

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertTrue(attestation["present"])
            self.assertTrue(attestation["valid"])
            self.assertFalse(attestation["available"])
            self.assertFalse(attestation["mandatory_ready"])
            self.assertEqual(attestation["registry_version"], 0)
            self.assertEqual(attestation["advisory_mode"], "unavailable")
            self.assertEqual(
                report["skill_selection_attestation"][
                    "mandatory_ready_run_count"
                ],
                0,
            )
            self.assertEqual(
                report["skill_selection_attestation"][
                    "unavailable_run_count"
                ],
                1,
            )

    def test_exact_reviewer_validation_repair_completes_one_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "reviewer-repair-test",
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
            primary_route = "codex-cli:gpt-5.5:high"
            reviewer_route = "codex-cli:gpt-5.6-sol:xhigh"
            prompt = {
                "alert": {"alert_id": "reviewer-repair-alert"},
                "evidence_reference_contract": {"references": []},
            }
            envelope = harness.JobEnvelope.from_prompt(
                run_id="reviewer-repair-run",
                prompt_package=prompt,
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=primary_route,
                configuration={"reviewer_route": reviewer_route},
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            primary_response = {
                "_analysis_model": "gpt-5.5",
                "_analysis_model_path": "frontier-codex-cli",
                "_analysis_provider": "codex-cli",
                "_analysis_model_route": primary_route,
            }
            run.preflight_model_call(
                call_id="primary-initial",
                input_value=prompt,
                requested_route=primary_route,
                purpose="initial primary analysis",
            )
            run.model_call(
                call_id="primary-initial",
                purpose="initial primary analysis",
                requested_route=primary_route,
                response=primary_response,
                input_value=prompt,
                duration_seconds=0.1,
            )
            run.record_response(
                {
                    "detection_outcome": "inconclusive",
                    "confidence": "medium",
                    "confidence_score": 0.5,
                },
                decision_id="primary",
                decision_type="primary-analysis",
                hypothesis_revision=1,
            )
            reviewer_response = {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "frontier-codex-cli",
                "_analysis_provider": "codex-cli",
                "_analysis_model_route": reviewer_route,
            }
            for attempt, status in (
                (1, "validation-failed"),
                (2, "completed"),
            ):
                call_id = f"independent-review-{attempt}"
                run.preflight_model_call(
                    call_id=call_id,
                    input_value=prompt,
                    requested_route=reviewer_route,
                    purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
                    independent_review=True,
                )
                run.model_call(
                    call_id=call_id,
                    purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
                    requested_route=reviewer_route,
                    response=reviewer_response,
                    input_value=prompt,
                    duration_seconds=0.1,
                    independent_review=True,
                    status=status,
                )
            run.record_response(
                {
                    "detection_outcome": "inconclusive",
                    "confidence": "medium",
                    "confidence_score": 0.5,
                },
                decision_id="independent-review",
                decision_type="independent-review",
                hypothesis_revision=1,
            )
            run.complete(check_budget=False)

            report = evaluator.evaluate_database(database, run.run_id)
            models = report["runs"][0]["models"]

            self.assertEqual(models["successful_call_count"], 2)
            self.assertEqual(models["purpose_count"], 2)
            self.assertEqual(
                models["terminally_successful_purpose_count"],
                2,
            )
            self.assertEqual(models["incomplete_purpose_count"], 0)
            self.assertEqual(models["exact_reviewer_repair_count"], 1)
            self.assertEqual(
                models["superseded_validation_failure_count"],
                1,
            )
            self.assertEqual(
                models["unexpected_unsuccessful_call_count"],
                0,
            )
            self.assertEqual(
                models["malformed_purpose_sequence_count"],
                0,
            )
            classifications = {
                item["call_id"]: item["classification"]
                for item in models["call_status_classifications"]
            }
            self.assertEqual(
                classifications["independent-review-1"],
                "superseded-validation-failure",
            )
            self.assertEqual(
                classifications["independent-review-2"],
                "successful",
            )
            self.assertNotIn(
                "model-purpose-incomplete",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertTrue(
                report["runs"][0]["reviewer"][
                    "completion_contract_satisfied"
                ]
            )
            self.assertEqual(
                report["models"]["exact_reviewer_repair_count"],
                1,
            )
            self.assertTrue(report["runs"][0]["integrity"]["valid"])

    def test_model_purpose_completion_rejects_malformed_retry_patterns(self):
        reviewer = {"has_reviewer_decision": True}

        def call(
            call_id,
            status,
            *,
            purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
            independent_review=1,
            created_at="2026-07-25T00:00:20Z",
        ):
            return {
                "call_id": call_id,
                "purpose": purpose,
                "requested_route": "codex-cli:gpt-5.6-sol:xhigh",
                "independent_review": independent_review,
                "status": status,
                "created_at": created_at,
            }

        accepted_single = evaluator.model_purpose_completion(
            [call("independent-review-1", "completed")],
            reviewer,
        )
        self.assertEqual(
            accepted_single["terminally_successful_purpose_count"],
            1,
        )
        self.assertEqual(
            accepted_single["malformed_purpose_sequence_count"],
            0,
        )

        malformed_cases = {
            "lone-validation-failure": [
                call("independent-review-1", "validation-failed"),
            ],
            "runtime-failure-then-success": [
                call("independent-review-1", "failed:RuntimeError"),
                call(
                    "independent-review-2",
                    "completed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "three-attempts": [
                call("independent-review-1", "validation-failed"),
                call(
                    "independent-review-2",
                    "validation-failed",
                    created_at="2026-07-25T00:00:30Z",
                ),
                call(
                    "independent-review-3",
                    "completed",
                    created_at="2026-07-25T00:00:40Z",
                ),
            ],
            "wrong-purpose": [
                call(
                    "independent-review-1",
                    "validation-failed",
                    purpose="renamed reviewer purpose",
                ),
                call(
                    "independent-review-2",
                    "completed",
                    purpose="renamed reviewer purpose",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "success-then-validation-failure": [
                call("independent-review-1", "completed"),
                call(
                    "independent-review-2",
                    "validation-failed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "renamed-single-reviewer": [
                call(
                    "renamed-review-call",
                    "completed",
                    purpose="renamed reviewer purpose",
                ),
            ],
            "empty-primary-purpose": [
                call(
                    "primary-empty-purpose",
                    "completed",
                    purpose="",
                    independent_review=0,
                ),
            ],
        }
        for label, calls in malformed_cases.items():
            with self.subTest(label=label):
                result = evaluator.model_purpose_completion(
                    calls,
                    reviewer,
                )
                self.assertEqual(result["exact_reviewer_repair_count"], 0)
                self.assertGreater(
                    result["malformed_purpose_sequence_count"],
                    0,
                )
                if label not in {
                    "renamed-single-reviewer",
                    "empty-primary-purpose",
                }:
                    self.assertGreater(
                        result["unexpected_unsuccessful_call_count"],
                        0,
                    )

        missing_decision = evaluator.model_purpose_completion(
            [
                call("independent-review-1", "validation-failed"),
                call(
                    "independent-review-2",
                    "completed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            {"has_reviewer_decision": False},
        )
        self.assertEqual(missing_decision["exact_reviewer_repair_count"], 0)
        self.assertEqual(
            missing_decision["malformed_purpose_sequence_count"],
            1,
        )
        self.assertEqual(
            missing_decision["unexpected_unsuccessful_call_count"],
            1,
        )

    def test_model_call_contract_is_closed_and_reviewer_is_conditional(self):
        primary = {
            "call_id": "primary-initial",
            "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
            "requested_route": "codex-cli:gpt-5.5:high",
            "independent_review": 0,
            "status": "completed",
            "created_at": "2026-07-25T00:00:10Z",
        }
        contract = evaluator.canonical_model_call_contract([primary])
        self.assertTrue(contract["valid"])
        self.assertEqual(contract["canonical_model_call_count"], 1)
        no_reviewer = {
            "model_call_count": 0,
            "completed_model_call_count": 0,
            "primary_decision_count": 1,
            "reviewer_decision_count": 0,
            "has_primary_decision": True,
            "has_reviewer_decision": False,
            "decision_comparable": False,
            "missing_reviewer_decision": False,
        }
        completion = evaluator.reviewer_completion_contract(
            no_reviewer,
            {"exact_reviewer_repair_count": 0},
        )
        self.assertFalse(completion["completion_contract_required"])
        self.assertTrue(completion["completion_contract_satisfied"])

        for field, value in (
            ("call_id", "invented-call"),
            ("purpose", "renamed purpose"),
            ("status", "success"),
        ):
            with self.subTest(field=field):
                changed = dict(primary)
                changed[field] = value
                rejected = evaluator.canonical_model_call_contract([changed])
                self.assertFalse(rejected["valid"])
                self.assertEqual(
                    rejected["noncanonical_model_call_count"],
                    1,
                )

        incomplete_reviewer = {
            **no_reviewer,
            "model_call_count": 1,
            "completed_model_call_count": 1,
            "reviewer_decision_count": 1,
            "has_reviewer_decision": True,
            "decision_comparable": False,
        }
        completion = evaluator.reviewer_completion_contract(
            incomplete_reviewer,
            {"exact_reviewer_repair_count": 0},
        )
        self.assertTrue(completion["completion_contract_required"])
        self.assertFalse(completion["completion_contract_satisfied"])

    def test_adjudication_is_canonical_but_not_a_second_reviewer(self):
        route = "codex-cli:gpt-5.6-sol:xhigh"
        reviewer_call = {
            "call_id": "independent-review-1",
            "purpose": evaluator.REVIEWER_REPAIR_PURPOSE,
            "requested_route": route,
            "independent_review": 1,
            "status": "completed",
            "created_at": "2026-07-25T00:00:20Z",
        }
        adjudication_call = {
            "call_id": "disagreement-adjudication-1",
            "purpose": evaluator.ADJUDICATION_PURPOSE,
            "requested_route": route,
            "independent_review": 1,
            "status": "completed",
            "created_at": "2026-07-25T00:00:30Z",
        }
        contract = evaluator.canonical_model_call_contract(
            [reviewer_call, adjudication_call]
        )
        self.assertFalse(contract["valid"])
        self.assertEqual(contract["noncanonical_model_call_count"], 0)
        self.assertIn(
            "primary-initial-count-not-one", contract["global_reasons"]
        )
        primary_call = {
            "call_id": evaluator.PRIMARY_INITIAL_CALL_ID,
            "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
            "requested_route": "codex-cli:gpt-5.5:high",
            "independent_review": 0,
            "status": "completed",
            "created_at": "2026-07-25T00:00:10Z",
        }
        complete_contract = evaluator.canonical_model_call_contract(
            [primary_call, reviewer_call, adjudication_call]
        )
        self.assertTrue(complete_contract["valid"])
        self.assertEqual(
            complete_contract["noncanonical_model_call_count"], 0
        )

        purpose = evaluator.model_purpose_completion(
            [reviewer_call, adjudication_call],
            {"has_reviewer_decision": True},
        )
        self.assertEqual(purpose["malformed_purpose_sequence_count"], 0)
        self.assertEqual(purpose["exact_reviewer_repair_count"], 0)
        self.assertEqual(purpose["exact_adjudication_repair_count"], 0)

        decisions = [
            {
                "decision_id": "primary",
                "decision_type": "primary-analysis",
                "payload_json": json.dumps(
                    {"detection_outcome": "inconclusive"}
                ),
            },
            {
                "decision_id": "independent-review",
                "decision_type": "independent-review",
                "payload_json": json.dumps(
                    {"detection_outcome": "informational_no_action"}
                ),
            },
        ]
        reviewer = evaluator.reviewer_result(
            [reviewer_call, adjudication_call], decisions, collections.Counter()
        )
        self.assertEqual(reviewer["model_call_count"], 1)
        completion = evaluator.reviewer_completion_contract(
            reviewer, purpose
        )
        self.assertTrue(completion["completion_contract_satisfied"])

    def test_supplemental_reviewer_call_is_bounded_and_canonical(self):
        primary_route = "codex-cli:gpt-5.5:high"
        reviewer_route = "codex-cli:gpt-5.6-sol:xhigh"
        calls = [
            {
                "call_id": evaluator.PRIMARY_INITIAL_CALL_ID,
                "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
                "requested_route": primary_route,
                "independent_review": 0,
                "status": "completed",
                "created_at": "2026-07-25T00:00:10Z",
            },
            {
                "call_id": "independent-review-1",
                "purpose": evaluator.REVIEWER_REPAIR_PURPOSE,
                "requested_route": reviewer_route,
                "independent_review": 1,
                "status": "completed",
                "created_at": "2026-07-25T00:00:20Z",
            },
            {
                "call_id": evaluator.SUPPLEMENTAL_REVIEW_CALL_ID,
                "purpose": evaluator.SUPPLEMENTAL_REVIEW_PURPOSE,
                "requested_route": reviewer_route,
                "independent_review": 1,
                "status": "completed",
                "created_at": "2026-07-25T00:00:30Z",
            },
        ]
        contract = evaluator.canonical_model_call_contract(calls)

        self.assertTrue(contract["valid"])
        self.assertEqual(contract["reviewer_model_call_count"], 2)
        self.assertEqual(contract["adjudicator_model_call_count"], 0)

        decisions = [
            {
                "decision_id": "primary",
                "decision_type": "primary-analysis",
                "payload_json": json.dumps(
                    {"detection_outcome": "inconclusive"}
                ),
            },
            {
                "decision_id": "independent-review",
                "decision_type": "independent-review",
                "payload_json": json.dumps(
                    {"detection_outcome": "informational_no_action"}
                ),
            },
        ]
        reviewer = evaluator.reviewer_result(
            calls, decisions, collections.Counter()
        )
        self.assertEqual(reviewer["model_call_count"], 2)
        self.assertEqual(reviewer["supplemental_model_call_count"], 1)
        purpose = evaluator.model_purpose_completion(calls, reviewer)
        completion = evaluator.reviewer_completion_contract(
            reviewer, purpose
        )
        self.assertTrue(completion["completion_contract_satisfied"])

    def test_model_call_contract_treats_planning_repair_as_followup_round(
        self,
    ):
        route = "codex-cli:gpt-5.5:high"

        def model_call(
            call_id: str,
            purpose: str,
            *,
            second: int,
            independent_review: int = 0,
            status: str = "completed",
        ) -> dict:
            return {
                "call_id": call_id,
                "purpose": purpose,
                "requested_route": route,
                "independent_review": independent_review,
                "status": status,
                "created_at": f"2026-07-25T00:00:{second:02d}Z",
            }

        initial = model_call(
            evaluator.PRIMARY_INITIAL_CALL_ID,
            evaluator.PRIMARY_INITIAL_PURPOSE,
            second=1,
        )
        repair = model_call(
            evaluator.QUERY_PLANNING_REPAIR_CALL_ID,
            evaluator.QUERY_PLANNING_REPAIR_PURPOSE,
            second=2,
        )
        followup_two = model_call(
            "primary-followup-2",
            "primary investigation follow-up round 2",
            second=3,
        )
        contract = evaluator.canonical_model_call_contract(
            [initial, repair, followup_two]
        )
        self.assertTrue(contract["valid"])
        self.assertEqual(contract["query_planning_repair_call_count"], 1)
        self.assertEqual(contract["primary_followup_call_count"], 1)
        self.assertEqual(contract["canonical_model_call_count"], 3)

        invalid_sequences = {
            "missing-repair-slot": [
                initial,
                followup_two,
            ],
            "reuses-repair-slot": [
                initial,
                repair,
                model_call(
                    "primary-followup-1",
                    "primary investigation follow-up round 1",
                    second=3,
                ),
            ],
            "skips-after-repair": [
                initial,
                repair,
                model_call(
                    "primary-followup-3",
                    "primary investigation follow-up round 3",
                    second=3,
                ),
            ],
            "duplicate-repair": [
                initial,
                repair,
                model_call(
                    evaluator.QUERY_PLANNING_REPAIR_CALL_ID,
                    evaluator.QUERY_PLANNING_REPAIR_PURPOSE,
                    second=3,
                ),
            ],
            "wrong-repair-purpose": [
                initial,
                {
                    **repair,
                    "purpose": "unbounded query repair",
                },
                followup_two,
            ],
        }
        for label, calls in invalid_sequences.items():
            with self.subTest(label=label):
                rejected = evaluator.canonical_model_call_contract(calls)
                self.assertFalse(rejected["valid"])
                self.assertGreater(rejected["violation_count"], 0)

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
                status="validation-failed",
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

    def test_projects_hash_bound_terminal_execution_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "terminal-execution-controls",
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
            route = "codex-cli:gpt-5.6-sol:high"
            envelope = harness.JobEnvelope.from_prompt(
                run_id="terminal-control-run",
                prompt_package={
                    "group_id": "1" * 20,
                    "alert": {"alert_id": "alert-terminal-control"},
                    "evidence_reference_contract": {"references": []},
                },
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                    "evaluation_memory_frozen": True,
                },
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            run.preflight_model_call(
                call_id="primary",
                input_value={"case": "terminal-control"},
                requested_route=route,
                purpose="primary analysis",
            )
            run.model_call(
                call_id="primary",
                purpose="primary analysis",
                requested_route=route,
                response={
                    "_analysis_model": "gpt-5.6-sol",
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_provider": "codex-cli",
                    "_analysis_model_route": route,
                },
                input_value={"case": "terminal-control"},
                duration_seconds=0.1,
            )
            run.complete(
                {
                    "analysis_id": run.run_id,
                    "submitted_response_sha256": "a" * 64,
                    "stored_response_sha256": "b" * 64,
                    "evaluation_memory_frozen": True,
                },
                check_budget=False,
            )

            report = evaluator.evaluate_database(database, run.run_id)
            result = report["runs"][0]
            self.assertEqual(result["assigned_route"], route)
            self.assertEqual(
                result["assigned_reviewer_route"],
                "codex-cli:gpt-5.6-sol:xhigh",
            )
            self.assertEqual(
                result["terminal_execution_summary"],
                {
                    "analysis_id": run.run_id,
                    "submitted_response_sha256": "a" * 64,
                    "stored_response_sha256": "b" * 64,
                    "evaluation_memory_frozen": True,
                },
            )
            self.assertEqual(
                result["models"]["successful_primary_call_count"],
                1,
            )
            self.assertTrue(result["integrity"]["valid"])

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
