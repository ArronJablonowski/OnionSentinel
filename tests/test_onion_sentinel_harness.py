import dataclasses
import contextlib
import gc
import importlib.util
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
import warnings
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "onion_sentinel_harness.py"
SPEC = importlib.util.spec_from_file_location(
    "onion_sentinel_harness_test_module",
    MODULE_PATH,
)
HARNESS = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class OnionSentinelHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "state" / "harness.sqlite3"
        self.policy_path = self.root / "config" / "harness-policy.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def policy_document(
        *,
        enabled: bool = True,
        mode: str = "shadow",
        budgets: dict | None = None,
        approval_required: list[str] | None = None,
    ) -> dict:
        effective_budgets = dict(HARNESS.DEFAULT_BUDGETS)
        effective_budgets.update(budgets or {})
        return {
            "schema": HARNESS.POLICY_SCHEMA,
            "version": "1.2.3",
            "enabled": enabled,
            "mode": mode,
            "budgets": effective_budgets,
            "role_capabilities": {
                role: sorted(capabilities)
                for role, capabilities in HARNESS.DEFAULT_ROLE_CAPABILITIES.items()
            },
            "approval_required": (
                [] if approval_required is None else approval_required
            ),
            "memory": {
                "require_independent_agreement": True,
                "shared_requires_human_approval": True,
            },
        }

    def write_policy(self, **overrides) -> HARNESS.HarnessPolicy:
        document = self.policy_document(**overrides)
        self.policy_path.parent.mkdir(parents=True)
        self.policy_path.write_text(
            json.dumps(document, sort_keys=True),
            encoding="utf-8",
        )
        return HARNESS.HarnessPolicy.from_dict(document)

    @staticmethod
    def prompt_package() -> dict:
        return {
            "alert": {
                "alert_id": "alert-42",
                "rule_name": "Synthetic read-only investigation alert",
            },
            "group_id": "group-42",
            "authorization": "Bearer never-persist-this-sensitive-value",
            "evidence_reference_contract": {
                "schema": "onion-sentinel-evidence-reference-contract-v1",
                "references": [
                    {
                        "ref": "alert:42",
                        "source": "security-onion-alert",
                        "source_class": "suricata_alert",
                        "status": "available",
                        "returned": 1,
                        "corroborating": True,
                    },
                    {
                        "ref": "zeek:uid-42",
                        "source": "zeek-conn",
                        "source_class": "zeek_conn",
                        "status": "available",
                        "returned": 1,
                        "corroborating": True,
                    },
                ],
            },
        }

    @staticmethod
    def response() -> dict:
        return {
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "codex-cli",
            "_analysis_provider": "openai",
            "_analysis_harness": "codex",
            "_analysis_model_route": "codex-cli:gpt-5.6-sol:high",
            "event_status": "observed",
            "detection_outcome": "true_positive_suspicious",
            "final_disposition_status": "reviewed",
            "confidence": "high",
            "confidence_score": 0.94,
            "executive_summary": "Two independent sources corroborated the event.",
            "detection_outcome_reasoning": "The alert and Zeek flow agree.",
            "evidence_used": ["alert:42", "zeek:uid-42"],
            "hypotheses": [
                {
                    "id": "supported-hypothesis",
                    "statement": "The network event occurred.",
                    "status": "supported",
                    "supporting_evidence": ["alert:42", "unknown:ignored"],
                    "contradicting_evidence": [],
                    "next_discriminator": "Collect endpoint process telemetry.",
                },
                {
                    "id": "unsupported-hypothesis",
                    "statement": "An unsupported assertion must remain unresolved.",
                    "status": "supported",
                    "supporting_evidence": ["unknown:missing"],
                    "contradicting_evidence": [],
                },
            ],
            "_evidence_reference_validation": {
                "invalid_refs": [],
                "corroborating_source_classes": [
                    "suricata_alert",
                    "zeek_conn",
                ],
            },
            "_second_opinion": {
                "status": "completed",
                "comparison": {
                    "agreement": "agreement",
                    "material_disagreement": False,
                },
            },
        }

    @staticmethod
    def envelope(
        run_id: str,
        prompt_package: dict | None = None,
        *,
        role: str = "soc-analyst",
    ):
        return HARNESS.JobEnvelope.from_prompt(
            run_id=run_id,
            prompt_package=prompt_package or OnionSentinelHarnessTests.prompt_package(),
            role=role,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={
                "query_mode": "read-only",
                "max_rounds": 3,
                "reviewer_route": "codex-cli:gpt-5.6-terra:high",
            },
        )

    def make_run(
        self,
        run_id: str = "run-42",
        *,
        policy: HARNESS.HarnessPolicy | None = None,
        db_path: Path | None = None,
        role: str = "soc-analyst",
    ):
        policy = policy or HARNESS.HarnessPolicy.from_dict(
            self.policy_document()
        )
        store = HARNESS.HarnessStore(db_path or self.db_path)
        return HARNESS.HarnessRun(
            store,
            self.envelope(run_id, role=role),
            policy,
        )

    def test_future_schema_rejection_does_not_mutate_sqlite_journal(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE harness_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO harness_metadata(key, value) VALUES(?, ?)",
                    ("schema_version", str(HARNESS.SQL_SCHEMA_VERSION + 1)),
                )
                journal_mode = connection.execute(
                    "PRAGMA journal_mode = DELETE"
                ).fetchone()[0]
        self.assertEqual(str(journal_mode).lower(), "delete")
        self.assertFalse(Path(f"{self.db_path}-wal").exists())
        self.assertFalse(Path(f"{self.db_path}-shm").exists())

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "newer runtime",
        ):
            HARNESS.HarnessStore(self.db_path)

        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            observed_mode = connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0]
        self.assertEqual(str(observed_mode).lower(), "delete")
        self.assertFalse(Path(f"{self.db_path}-wal").exists())
        self.assertFalse(Path(f"{self.db_path}-shm").exists())

    @staticmethod
    def budget_events(run) -> list[dict]:
        return [
            event
            for event in run.store.export_trace(run.run_id)["events"]
            if event["event_type"] == "policy.budget"
        ]

    @staticmethod
    def age_run(run) -> None:
        with HARNESS._connect(run.store.path) as connection:
            connection.execute(
                """
                UPDATE harness_runs
                SET started_at = '2000-01-01T00:00:00Z'
                WHERE run_id = ?
                """,
                (run.run_id,),
            )

    @staticmethod
    def replace_terminal_manifest(
        run,
        manifest: dict | None,
        *,
        legacy_identity: bool = False,
    ) -> None:
        """Rewrite terminal metadata while preserving a valid event hash chain."""
        with HARNESS._connect(run.store.path) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM harness_events
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (run.run_id,),
            ).fetchall()
            previous = "0" * 64
            for row in rows:
                payload = json.loads(row["payload_json"])
                if (
                    legacy_identity
                    and row["event_type"] == "run.started"
                ):
                    payload.pop("assigned_reviewer_route", None)
                if row["event_type"] == "run.succeeded":
                    if manifest is None:
                        payload.pop("ledger_manifest", None)
                    else:
                        payload["ledger_manifest"] = manifest
                payload_json = HARNESS.canonical_json(payload)
                payload_sha256 = HARNESS.hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                body = {
                    "run_id": run.run_id,
                    "sequence": int(row["sequence"]),
                    "idempotency_key": row["idempotency_key"],
                    "event_type": row["event_type"],
                    "stage": row["stage"],
                    "created_at": row["created_at"],
                    "payload_sha256": payload_sha256,
                    "previous_event_sha256": previous,
                }
                event_sha256 = HARNESS.digest_json(body)
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
                        run.run_id,
                        row["sequence"],
                    ),
                )
                previous = event_sha256

    def test_policy_parsing_is_default_deny_and_all_mutations_require_approval(
        self,
    ) -> None:
        # Even an empty approval list cannot accidentally remove the mandatory
        # mutation approval gate.
        policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(approval_required=[])
        )
        read = policy.authorize(
            HARNESS.AgentRole.SOC_ANALYST.value,
            "security-onion.events.query",
        )
        self.assertTrue(read.allowed)
        self.assertFalse(read.requires_approval)

        mutation = policy.authorize(
            HARNESS.AgentRole.SOC_ANALYST.value,
            "cases.write",
        )
        self.assertFalse(mutation.allowed)
        self.assertTrue(mutation.requires_approval)
        self.assertIn("human approval", mutation.reason)
        self.assertTrue(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "cases.write",
                approved=True,
            ).allowed
        )

        self.assertFalse(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "response.contain",
                approved=True,
            ).allowed
        )
        self.assertFalse(
            policy.authorize("unregistered-role", "alerts.read").allowed
        )
        self.assertFalse(
            policy.authorize(
                HARNESS.AgentRole.SOC_ANALYST.value,
                "shell.execute",
            ).allowed
        )

    def test_policy_rejects_unknown_fields_capabilities_and_unsafe_shapes(
        self,
    ) -> None:
        document = self.policy_document()
        document["unexpected"] = True
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "unsupported harness policy fields",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document()
        document["role_capabilities"]["soc-analyst"].append("shell.execute")
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "unknown capabilities",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document()
        document["enabled"] = "yes"
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "enabled must be boolean",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

        document = self.policy_document(
            budgets={"max_queries_total": 0},
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "outside its safe range",
        ):
            HARNESS.HarnessPolicy.from_dict(document)

    def test_policy_rejects_incomplete_and_weakly_typed_documents(self) -> None:
        cases = []

        document = self.policy_document()
        del document["version"]
        cases.append(("missing top-level field", document, "missing required"))

        document = self.policy_document()
        del document["budgets"]["max_model_calls"]
        cases.append(("missing budget", document, "missing required harness budgets"))

        document = self.policy_document()
        del document["memory"]
        cases.append(("missing memory object", document, "missing required"))

        document = self.policy_document()
        del document["memory"]["require_independent_agreement"]
        cases.append(("missing memory flag", document, "missing required memory"))

        for label, raw_value in (
            ("numeric string", "6"),
            ("floating point", 6.0),
        ):
            document = self.policy_document()
            document["budgets"]["max_model_calls"] = raw_value
            cases.append((label, document, "must be an integer"))

        document = self.policy_document()
        capability = document["role_capabilities"]["soc-analyst"][0]
        document["role_capabilities"]["soc-analyst"].append(capability)
        cases.append(("duplicate capability", document, "unique array"))

        document = self.policy_document()
        document["role_capabilities"]["soc-analyst"].append(7)
        cases.append(("non-string capability", document, "entries must be strings"))

        document = self.policy_document(
            approval_required=["cases.write", "cases.write"]
        )
        cases.append(("duplicate approval", document, "unique array"))

        document = self.policy_document(approval_required=["cases.write", 7])
        cases.append(("non-string approval", document, "array of strings"))

        for label, document, message in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    HARNESS.HarnessPolicyError,
                    message,
                ):
                    HARNESS.HarnessPolicy.from_dict(document)

    def test_policy_schema_limits_align_with_runtime_constants(self) -> None:
        schema_path = (
            ROOT
            / "n8n"
            / "config"
            / "investigation_harness_policy.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), set(HARNESS.REQUIRED_POLICY_FIELDS))

        budget_schema = schema["properties"]["budgets"]
        self.assertEqual(
            set(budget_schema["required"]),
            set(HARNESS.DEFAULT_BUDGETS),
        )
        for name in HARNESS.DEFAULT_BUDGETS:
            with self.subTest(budget=name):
                definition = budget_schema["properties"][name]
                self.assertEqual(definition["type"], "integer")
                self.assertEqual(definition["minimum"], HARNESS.MIN_BUDGETS[name])
                self.assertEqual(definition["maximum"], HARNESS.MAX_BUDGETS[name])

        memory_schema = schema["properties"]["memory"]
        self.assertEqual(
            set(memory_schema["required"]),
            set(HARNESS.REQUIRED_MEMORY_FIELDS),
        )
        self.assertEqual(
            set(schema["properties"]["role_capabilities"]["required"]),
            {role.value for role in HARNESS.AgentRole},
        )
        capabilities_schema = schema["$defs"]["capabilities"]
        self.assertTrue(capabilities_schema["uniqueItems"])
        self.assertEqual(
            set(capabilities_schema["items"]["enum"]),
            set(HARNESS.ALL_CAPABILITIES),
        )

    def test_policy_loader_rejects_group_or_world_writable_file(self) -> None:
        self.write_policy()
        self.policy_path.chmod(0o666)
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "must not be group- or world-writable",
        ):
            HARNESS.load_policy(self.policy_path)

    def test_missing_or_disabled_policy_does_not_create_runtime_state(self) -> None:
        missing_policy = self.root / "missing-policy.json"
        policy = HARNESS.load_policy(missing_policy)
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.mode, "shadow")

        result = HARNESS.start_harness_run(
            run_id="disabled-run",
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"mode": "read-only"},
            policy_path=missing_policy,
            db_path=self.db_path,
        )
        self.assertIsNone(result)
        self.assertFalse(self.db_path.exists())

        self.write_policy(enabled=False)
        result = HARNESS.start_harness_run(
            run_id="explicitly-disabled-run",
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"mode": "read-only"},
            policy_path=self.policy_path,
            db_path=self.db_path,
        )
        self.assertIsNone(result)
        self.assertFalse(self.db_path.exists())

    def test_prompt_execution_lineage_drives_soc_manual_and_automatic_tasks(
        self,
    ) -> None:
        stable_group_id = "abcdef1234567890abcd"
        manual_package = self.prompt_package()
        manual_package.update(
            {
                "group_id": stable_group_id,
                "manual_reanalysis": True,
            }
        )
        automatic_package = self.prompt_package()
        automatic_package.update(
            {
                "group_id": stable_group_id,
                "manual_reanalysis": False,
            }
        )

        manual = self.envelope(
            "manual-lineage-run",
            prompt_package=manual_package,
        )
        automatic = self.envelope(
            "automatic-lineage-run",
            prompt_package=automatic_package,
        )

        self.assertEqual(manual.correlation_id, stable_group_id)
        self.assertEqual(manual.task_kind, "reanalysis")
        self.assertEqual(automatic.correlation_id, stable_group_id)
        self.assertEqual(automatic.task_kind, "alert-triage")

    def test_external_agent_routes_never_start_or_create_harness_state(
        self,
    ) -> None:
        policy = self.write_policy(enabled=True)
        cases = (
            (
                "Hermes primary",
                "hermes-agent:gpt-5.6-sol:medium",
                "ollama:gemma4:31b",
            ),
            (
                "OpenClaw primary",
                "openclaw:ollama/gemma4:26b-mlx:high",
                "",
            ),
            (
                "Hermes reviewer",
                "codex-cli:gpt-5.6-sol:high",
                "hermes-agent:gpt-5.6-sol:medium",
            ),
            (
                "OpenClaw malformed reviewer",
                "ollama:devstral-small-2:24b",
                "openclaw:malformed",
            ),
        )
        for index, (label, assigned, reviewer) in enumerate(cases):
            with self.subTest(label=label):
                db_path = self.root / f"external-{index}" / "harness.sqlite3"
                result = HARNESS.start_harness_run(
                    run_id=f"external-route-{index}",
                    prompt_package=self.prompt_package(),
                    role=HARNESS.AgentRole.SOC_ANALYST.value,
                    assigned_route=assigned,
                    configuration={
                        "mode": "read-only",
                        "reviewer_route": reviewer,
                    },
                    policy=policy,
                    db_path=db_path,
                )
                self.assertIsNone(result)
                self.assertFalse(db_path.exists())
                self.assertFalse(db_path.parent.exists())

    def test_sqlite_store_is_owner_only(self) -> None:
        store = HARNESS.HarnessStore(self.db_path)
        self.assertEqual(
            stat.S_IMODE(os.stat(store.path).st_mode),
            stat.S_IRUSR | stat.S_IWUSR,
        )

    def test_sqlite_connections_close_without_resource_warnings(self) -> None:
        run = self.make_run("connection-close-run")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            for _ in range(10):
                run.store.snapshot(run.run_id)
                run.store.verify_chain(run.run_id)
                run.store.export_trace(run.run_id)
            gc.collect()
        resource_warnings = [
            warning
            for warning in caught
            if issubclass(warning.category, ResourceWarning)
        ]
        self.assertEqual(resource_warnings, [])

    def test_sqlite_database_and_active_wal_sidecars_are_owner_only(self) -> None:
        store = HARNESS.HarnessStore(self.db_path)
        wal_path = Path(f"{self.db_path}-wal")
        shm_path = Path(f"{self.db_path}-shm")
        with HARNESS._connect(store.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sidecar_mode_probe(value INTEGER)"
            )
            connection.execute(
                "INSERT INTO sidecar_mode_probe(value) VALUES(1)"
            )
            present = [
                path
                for path in (store.path, wal_path, shm_path)
                if path.exists()
            ]
            self.assertIn(store.path, present)
            self.assertTrue(wal_path.exists() or shm_path.exists())
            for path in present:
                self.assertEqual(
                    stat.S_IMODE(os.stat(path).st_mode),
                    stat.S_IRUSR | stat.S_IWUSR,
                    path.name,
                )

        for path in (store.path, wal_path, shm_path):
            if path.exists():
                self.assertEqual(
                    stat.S_IMODE(os.stat(path).st_mode),
                    stat.S_IRUSR | stat.S_IWUSR,
                    path.name,
                )

    def test_full_lifecycle_exports_a_complete_secret_safe_trace(self) -> None:
        self.write_policy(enabled=True)
        run = HARNESS.start_harness_run(
            run_id="lifecycle-run",
            prompt_package=self.prompt_package(),
            role=HARNESS.AgentRole.SOC_ANALYST.value,
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={"query_mode": "read-only"},
            policy_path=self.policy_path,
            db_path=self.db_path,
        )
        self.assertIsNotNone(run)
        assert run is not None

        run.phase(
            "primary_analysis",
            route="codex-cli:gpt-5.6-sol:high",
            reason="primary investigation",
        )
        response = self.response()
        run.preflight_model_call(
            call_id="primary-1",
            input_value={
                "prompt": "sensitive prompt body",
                "api_token": "must-not-be-exported",
            },
            requested_route=run.envelope.assigned_route,
            purpose="primary investigation",
        )
        run.model_call(
            call_id="primary-1",
            purpose="primary investigation",
            requested_route="codex-cli:gpt-5.6-sol:high",
            response=response,
            input_value={
                "prompt": "sensitive prompt body",
                "api_token": "must-not-be-exported",
            },
            duration_seconds=1.234,
        )
        query_digest = "a" * 64
        result_digest = "b" * 64
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "q-1",
                        "backend": "elastic",
                        "purpose": "Corroborate the alert against network events.",
                        "query": {"query": {"term": {"network.community_id": "1:test"}}},
                    }
                ],
                "results": [
                    {
                        "query_id": "q-1",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {
                            "coverage": "bounded-time-window",
                            "returned_rows": 2,
                            "truncated": False,
                        },
                        "trusted_query_audit": [
                            {
                                "query_id": "q-1",
                                "query_digest": query_digest,
                                "result_digest": result_digest,
                                "evidence_ref": "query:elastic:q-1",
                                "status": "ok",
                                "returned_rows": 2,
                                "truncated": False,
                            }
                        ],
                    }
                ],
            }
        )
        run.record_response(
            response,
            decision_id="primary-decision",
            decision_type="alert-triage",
            hypothesis_revision=1,
        )
        run.store.append_event(
            run.run_id,
            "security.redaction-check",
            HARNESS.Stage.POST_PROCESSING.value,
            {
                "api_token": "literal-secret-must-not-appear",
                "note": (
                    "Bearer abcdefghijklmnopqrstuvwxyz0123456789 "
                    "must be redacted"
                ),
            },
            idempotency_key="security.redaction-check",
        )
        run.complete(
            {
                "artifact_digest": "c" * 64,
                "password": "literal-summary-secret",
            }
        )

        snapshot = run.store.snapshot(run.run_id)
        self.assertEqual(snapshot["status"], HARNESS.RunStatus.SUCCEEDED.value)
        self.assertEqual(snapshot["stage"], HARNESS.Stage.COMPLETE.value)
        self.assertEqual(snapshot["counts"]["evidence"], 3)
        self.assertEqual(snapshot["counts"]["hypotheses"], 2)
        self.assertEqual(snapshot["counts"]["decisions"], 1)
        self.assertEqual(snapshot["counts"]["model_calls"], 1)
        self.assertEqual(snapshot["counts"]["tool_calls"], 1)

        trace = run.store.export_trace(run.run_id)
        self.assertEqual(trace["schema"], HARNESS.TRACE_SCHEMA)
        self.assertTrue(trace["integrity"]["valid"])
        self.assertEqual(trace["model_calls"][0]["observed_model"], "gpt-5.6-sol")
        self.assertEqual(trace["model_calls"][0]["duration_ms"], 1234)
        self.assertEqual(trace["tool_calls"][0]["capability"], "security-onion.events.query")
        self.assertEqual(trace["tool_calls"][0]["coverage"], "bounded-time-window")
        decision_payload = json.loads(trace["decisions"][0]["payload_json"])
        self.assertEqual(
            decision_payload["response_digest"],
            HARNESS.digest_json(response),
        )
        decision_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "decision.recorded"
        )
        self.assertEqual(
            json.loads(decision_event["payload_json"])["response_digest"],
            HARNESS.digest_json(response),
        )
        hypothesis_status = {
            item["hypothesis_id"]: item["status"]
            for item in trace["hypotheses"]
        }
        self.assertEqual(hypothesis_status["supported-hypothesis"], "supported")
        self.assertEqual(hypothesis_status["unsupported-hypothesis"], "unresolved")

        serialized_trace = json.dumps(trace, sort_keys=True)
        self.assertNotIn("never-persist-this-sensitive-value", serialized_trace)
        self.assertNotIn("sensitive prompt body", serialized_trace)
        self.assertNotIn("must-not-be-exported", serialized_trace)
        self.assertNotIn("literal-secret-must-not-appear", serialized_trace)
        self.assertNotIn("literal-summary-secret", serialized_trace)
        self.assertIn("[redacted-sensitive-field]", serialized_trace)
        self.assertIn("[redacted-sensitive-value]", serialized_trace)

    def test_hash_chain_detects_payload_tampering(self) -> None:
        run = self.make_run("tamper-run")
        run.phase("primary_analysis", reason="before tamper")
        self.assertTrue(run.store.verify_chain(run.run_id)["valid"])

        with HARNESS._connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE harness_events
                SET payload_json = '{"tampered":true}'
                WHERE run_id = ? AND sequence = 2
                """,
                (run.run_id,),
            )
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertTrue(
            any("payload digest mismatch" in item for item in verification["errors"])
        )

    def test_terminal_ledger_manifest_detects_direct_ledger_tampering(self) -> None:
        run = self.make_run("terminal-ledger-tamper")
        run.catalogue_prompt_evidence(self.prompt_package())
        run.complete()

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])

        with HARNESS._connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE harness_evidence
                SET status = 'tampered-after-completion'
                WHERE run_id = ? AND evidence_ref = 'alert:42'
                """,
                (run.run_id,),
            )

        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])
        self.assertIn(
            "terminal ledger manifest mismatch",
            verification["errors"],
        )

    def test_current_terminal_manifest_is_v2_and_required(self) -> None:
        run = self.make_run("terminal-manifest-v2")
        run.complete()

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertEqual(
            verification["ledger_manifest_schema"],
            HARNESS.LEDGER_MANIFEST_SCHEMA,
        )
        self.assertEqual(
            HARNESS.LEDGER_MANIFEST_SCHEMA,
            "onion-sentinel-harness-ledger-manifest-v2",
        )

        self.replace_terminal_manifest(run, None)
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertFalse(verification["ledger_manifest_bound"])
        self.assertIn(
            "terminal ledger manifest is missing or malformed",
            verification["errors"],
        )

    def test_legacy_v1_terminal_manifest_survives_v4_projection(self) -> None:
        run = self.make_run("terminal-manifest-v1")
        run.complete()
        with HARNESS._connect(run.store.path) as connection:
            legacy_manifest = HARNESS.ledger_manifest(
                connection,
                run.run_id,
                schema=HARNESS.LEDGER_MANIFEST_SCHEMA_V1,
            )
        self.replace_terminal_manifest(run, legacy_manifest)
        verification = run.store.verify_chain(run.run_id)
        self.assertFalse(verification["valid"])
        self.assertIn(
            "terminal ledger manifest schema downgrade",
            verification["errors"],
        )

        self.replace_terminal_manifest(
            run,
            legacy_manifest,
            legacy_identity=True,
        )

        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])
        self.assertEqual(
            verification["ledger_manifest_schema"],
            HARNESS.LEDGER_MANIFEST_SCHEMA_V1,
        )

    def test_terminal_run_rejects_events_and_evidence_without_state_drift(
        self,
    ) -> None:
        run = self.make_run("terminal-immutable-run")
        run.complete()
        before = run.store.snapshot(run.run_id)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "terminal harness run is immutable",
        ):
            run.store.append_event(
                run.run_id,
                "late.event",
                HARNESS.Stage.POST_PROCESSING.value,
                {"should": "not persist"},
                idempotency_key="late.event",
            )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "terminal harness run is immutable",
        ):
            run.store.register_evidence(
                run.run_id,
                evidence_ref="late:evidence",
                source="test",
                source_class="test",
                trust_tier=HARNESS.TrustTier.READ_ONLY_BACKEND.value,
                corroborating=False,
                status="late",
            )

        after = run.store.snapshot(run.run_id)
        self.assertEqual(after["status"], HARNESS.RunStatus.SUCCEEDED.value)
        self.assertEqual(after["stage"], HARNESS.Stage.COMPLETE.value)
        self.assertEqual(after["counts"]["events"], before["counts"]["events"])
        self.assertEqual(after["counts"]["evidence"], before["counts"]["evidence"])
        verification = run.store.verify_chain(run.run_id)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["ledger_manifest_bound"])

    def test_event_idempotency_is_replay_safe_and_rejects_collision(self) -> None:
        run = self.make_run("idempotency-run")
        first = run.store.append_event(
            run.run_id,
            "test.event",
            HARNESS.Stage.POST_PROCESSING.value,
            {"value": 1},
            idempotency_key="stable-key",
        )
        replay = run.store.append_event(
            run.run_id,
            "test.event",
            HARNESS.Stage.POST_PROCESSING.value,
            {"value": 1},
            idempotency_key="stable-key",
        )
        self.assertEqual(first["event_id"], replay["event_id"])
        self.assertEqual(run.store.snapshot(run.run_id)["counts"]["events"], 2)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "idempotency key was reused",
        ):
            run.store.append_event(
                run.run_id,
                "test.event",
                HARNESS.Stage.POST_PROCESSING.value,
                {"value": 2},
                idempotency_key="stable-key",
            )

    def test_evidence_references_are_immutable(self) -> None:
        run = self.make_run("evidence-run")
        kwargs = {
            "evidence_ref": "elastic:event-1",
            "source": "elastic",
            "source_class": "security_onion_event",
            "trust_tier": HARNESS.TrustTier.READ_ONLY_BACKEND.value,
            "corroborating": True,
            "status": "ok",
            "evidence_digest": "d" * 64,
            "metadata": {"returned_rows": 1},
        }
        run.store.register_evidence(run.run_id, **kwargs)
        run.store.register_evidence(run.run_id, **kwargs)
        self.assertEqual(run.store.snapshot(run.run_id)["counts"]["evidence"], 1)

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "immutable evidence reference collides",
        ):
            run.store.register_evidence(
                run.run_id,
                **{**kwargs, "evidence_digest": "e" * 64},
            )

    def test_model_and_tool_call_ids_are_immutable(self) -> None:
        run = self.make_run("call-collision-run")
        response = self.response()
        model_kwargs = {
            "call_id": "model-1",
            "purpose": "triage",
            "requested_route": "codex-cli:gpt-5.6-sol:high",
            "response": response,
            "independent_review": False,
            "input_digest": "f" * 64,
            "duration_ms": 100,
        }
        run.store.record_model_call(run.run_id, **model_kwargs)
        run.store.record_model_call(
            run.run_id,
            **{**model_kwargs, "duration_ms": 999},
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "model call_id collides",
        ):
            run.store.record_model_call(
                run.run_id,
                **{
                    **model_kwargs,
                    "response": {**response, "confidence_score": 0.01},
                },
            )

        tool_kwargs = {
            "call_id": "tool-1",
            "round_number": 1,
            "backend": "elastic",
            "capability": "security-onion.events.query",
            "purpose": "corroborate",
            "request_digest": "1" * 64,
            "result_digest": "2" * 64,
            "status": "ok",
            "read_only": True,
            "coverage": "bounded",
            "truncated": False,
        }
        run.store.record_tool_call(run.run_id, **tool_kwargs)
        run.store.record_tool_call(run.run_id, **tool_kwargs)
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "tool call_id collides",
        ):
            run.store.record_tool_call(
                run.run_id,
                **{**tool_kwargs, "result_digest": "3" * 64},
            )

    def test_query_budgets_audit_in_shadow_and_block_in_enforce(self) -> None:
        constrained = {"max_queries_total": 1, "max_queries_per_round": 1}
        shadow_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="shadow", budgets=constrained)
        )
        shadow = self.make_run(
            "shadow-budget-run",
            policy=shadow_policy,
            db_path=self.root / "shadow.sqlite3",
        )
        over_budget_round = {
            "round": 1,
            "requests": [
                {"query_id": "q-1", "backend": "elastic", "purpose": "first"},
                {"query_id": "q-2", "backend": "oql", "purpose": "second"},
            ],
            "results": [],
        }
        shadow.query_round(over_budget_round)
        trace = shadow.store.export_trace(shadow.run_id)
        query_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "queries.completed"
        )
        self.assertEqual(
            set(query_event["payload"]["budget_violations"]),
            {"max_queries_total", "max_queries_per_round"},
        )
        self.assertEqual(trace["integrity"]["valid"], True)

        enforce_policy = dataclasses.replace(shadow_policy, mode="enforce")
        enforce = self.make_run(
            "enforce-budget-run",
            policy=enforce_policy,
            db_path=self.root / "enforce.sqlite3",
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "exceeds harness budget",
        ):
            enforce.query_round(over_budget_round)
        enforced_trace = enforce.store.export_trace(enforce.run_id)
        self.assertTrue(
            any(
                event["event_type"] == "policy.budget"
                for event in enforced_trace["events"]
            )
        )
        self.assertFalse(
            any(
                event["event_type"] == "queries.completed"
                for event in enforced_trace["events"]
            )
        )
        self.assertTrue(enforced_trace["integrity"]["valid"])

    def test_concurrent_model_preflight_allows_exactly_one_reservation(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(
                mode="enforce",
                budgets={"max_model_calls": 1},
            )
        )
        first = self.make_run("concurrent-model-budget", policy=policy)
        second = HARNESS.HarnessRun(
            HARNESS.HarnessStore(self.db_path),
            first.envelope,
            policy,
        )
        barrier = threading.Barrier(3)
        outcome_lock = threading.Lock()
        outcomes: list[tuple[str, str, object]] = []

        def reserve(run, call_id: str) -> None:
            try:
                barrier.wait(timeout=10)
                run.preflight_model_call(
                    call_id=call_id,
                    input_value={"context": "small"},
                    requested_route=run.envelope.assigned_route,
                    purpose="concurrent budget test",
                )
            except Exception as exc:  # captured for deterministic main-thread assertions
                outcome = ("error", call_id, exc)
            else:
                outcome = ("reserved", call_id, None)
            with outcome_lock:
                outcomes.append(outcome)

        workers = [
            threading.Thread(target=reserve, args=(first, "parallel-a")),
            threading.Thread(target=reserve, args=(second, "parallel-b")),
        ]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive(), "model reservation worker hung")

        self.assertEqual(len(outcomes), 2)
        reserved = [item for item in outcomes if item[0] == "reserved"]
        rejected = [item for item in outcomes if item[0] == "error"]
        self.assertEqual(len(reserved), 1)
        self.assertEqual(len(rejected), 1)
        self.assertIsInstance(rejected[0][2], HARNESS.HarnessPolicyError)
        self.assertIn("max_model_calls", str(rejected[0][2]))

        with HARNESS._connect(self.db_path) as connection:
            reservations = connection.execute(
                """
                SELECT reservation_id
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = 'model-call'
                """,
                (first.run_id,),
            ).fetchall()
        self.assertEqual([row["reservation_id"] for row in reservations], [reserved[0][1]])
        self.assertTrue(first.store.verify_chain(first.run_id)["valid"])

    def test_model_preflight_binds_primary_and_reviewer_routes(self) -> None:
        enforce_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="enforce")
        )
        primary = self.make_run(
            "primary-route-binding",
            policy=enforce_policy,
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "does not match",
        ):
            primary.preflight_model_call(
                call_id="primary-wrong-route",
                input_value={"context": "small"},
                requested_route="ollama:unexpected-model",
                purpose="initial primary analysis",
            )
        primary_trace = primary.store.export_trace(primary.run_id)
        route_events = [
            event
            for event in primary_trace["events"]
            if event["event_type"] == "policy.model-route"
        ]
        self.assertEqual(len(route_events), 1)
        self.assertFalse(
            json.loads(route_events[0]["payload_json"])["allowed"]
        )
        self.assertEqual(primary_trace["budget_reservations"], [])

        reviewer = self.make_run(
            "reviewer-route-binding",
            policy=enforce_policy,
            db_path=self.root / "reviewer-route-binding.sqlite3",
        )
        reviewer.preflight_model_call(
            call_id="reviewer-assigned-route",
            input_value={"context": "small"},
            requested_route=reviewer.envelope.assigned_reviewer_route,
            purpose="independent second-opinion review",
            independent_review=True,
        )
        reviewer_trace = reviewer.store.export_trace(reviewer.run_id)
        reviewer_route_event = next(
            event
            for event in reviewer_trace["events"]
            if event["event_type"] == "policy.model-route"
        )
        reviewer_payload = json.loads(
            reviewer_route_event["payload_json"]
        )
        self.assertTrue(reviewer_payload["allowed"])
        self.assertEqual(
            reviewer_payload["expected_route"],
            reviewer.envelope.assigned_reviewer_route,
        )
        self.assertTrue(reviewer_payload["independent_review"])

        observed_mismatch = self.make_run(
            "observed-route-mismatch",
            policy=enforce_policy,
            db_path=self.root / "observed-route-mismatch.sqlite3",
        )
        observed_mismatch.preflight_model_call(
            call_id="observed-wrong-route",
            input_value={"context": "small"},
            requested_route=observed_mismatch.envelope.assigned_route,
            purpose="observed route test",
        )
        mismatched_response = self.response()
        mismatched_response["_analysis_model_route"] = "ollama:gemma4:31b"
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "observed route differs",
        ):
            observed_mismatch.model_call(
                call_id="observed-wrong-route",
                purpose="observed route test",
                requested_route=observed_mismatch.envelope.assigned_route,
                response=mismatched_response,
                input_value={"context": "small"},
                duration_seconds=0.01,
            )
        mismatch_trace = observed_mismatch.store.export_trace(
            observed_mismatch.run_id
        )
        self.assertEqual(mismatch_trace["model_calls"], [])
        self.assertFalse(
            json.loads(
                next(
                    event["payload_json"]
                    for event in mismatch_trace["events"]
                    if event["event_type"] == "policy.model-observation"
                )
            )["allowed"]
        )

        missing_preflight = self.make_run(
            "missing-model-preflight",
            policy=enforce_policy,
            db_path=self.root / "missing-model-preflight.sqlite3",
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessPolicyError,
            "no matching allowed preflight",
        ):
            missing_preflight.model_call(
                call_id="not-preflighted",
                purpose="must be rejected",
                requested_route=missing_preflight.envelope.assigned_route,
                response=self.response(),
                input_value={"context": "small"},
                duration_seconds=0.01,
            )

        shadow_policy = HARNESS.HarnessPolicy.from_dict(
            self.policy_document(mode="shadow")
        )
        shadow = self.make_run(
            "shadow-route-mismatch",
            policy=shadow_policy,
            db_path=self.root / "shadow-route-mismatch.sqlite3",
        )
        shadow.preflight_model_call(
            call_id="shadow-mismatch",
            input_value={"context": "small"},
            requested_route="ollama:unexpected-model",
            purpose="shadow route audit",
        )
        shadow_trace = shadow.store.export_trace(shadow.run_id)
        self.assertEqual(len(shadow_trace["budget_reservations"]), 1)
        self.assertFalse(
            json.loads(
                next(
                    event["payload_json"]
                    for event in shadow_trace["events"]
                    if event["event_type"] == "policy.model-route"
                )
            )["allowed"]
        )

    def test_model_count_prompt_bytes_and_evidence_rows_shadow_and_enforce(
        self,
    ) -> None:
        cases = {
            "max_model_calls": {
                "budgets": {"max_model_calls": 1},
                "input": {"context": "small"},
                "prepare_existing_call": True,
            },
            "max_prompt_evidence_bytes": {
                "budgets": {"max_prompt_evidence_bytes": 4_096},
                "input": {"context": "x" * 8_192},
                "prepare_existing_call": False,
            },
            "max_prompt_evidence_rows": {
                "budgets": {"max_prompt_evidence_rows": 1},
                "input": {"rows": [{"event": 1}, {"event": 2}]},
                "prepare_existing_call": False,
            },
        }
        for violation, case in cases.items():
            for mode in ("shadow", "enforce"):
                with self.subTest(violation=violation, mode=mode):
                    policy = HARNESS.HarnessPolicy.from_dict(
                        self.policy_document(
                            mode=mode,
                            budgets=case["budgets"],
                        )
                    )
                    run = self.make_run(
                        f"{violation}-{mode}",
                        policy=policy,
                        db_path=self.root / f"{violation}-{mode}.sqlite3",
                    )
                    if case["prepare_existing_call"]:
                        run.preflight_model_call(
                            call_id="existing-model-call",
                            input_value={"context": "first"},
                            requested_route=run.envelope.assigned_route,
                            purpose="establish model-call usage",
                        )
                        run.model_call(
                            call_id="existing-model-call",
                            purpose="establish model-call usage",
                            requested_route="codex-cli:gpt-5.6-sol:high",
                            response=self.response(),
                            input_value={"context": "first"},
                            duration_seconds=0.01,
                        )

                    operation = lambda: run.preflight_model_call(
                        call_id=f"next-{violation}",
                        input_value=case["input"],
                        requested_route=run.envelope.assigned_route,
                        purpose=f"{violation} budget test",
                    )
                    if mode == "enforce":
                        with self.assertRaisesRegex(
                            HARNESS.HarnessPolicyError,
                            violation,
                        ):
                            operation()
                    else:
                        operation()

                    events = self.budget_events(run)
                    matching_events = [
                        event
                        for event in events
                        if violation in event["payload"]["violations"]
                    ]
                    self.assertEqual(len(matching_events), 1)
                    self.assertIn(
                        violation,
                        matching_events[0]["payload"]["violations"],
                    )
                    self.assertEqual(
                        matching_events[0]["payload"]["policy_mode"],
                        mode,
                    )
                    self.assertTrue(run.store.verify_chain(run.run_id)["valid"])

    def test_runtime_budget_is_audited_in_shadow_and_blocks_enforcement(
        self,
    ) -> None:
        for mode in ("shadow", "enforce"):
            with self.subTest(mode=mode):
                policy = HARNESS.HarnessPolicy.from_dict(
                    self.policy_document(
                        mode=mode,
                        budgets={"max_run_seconds": 1},
                    )
                )
                run = self.make_run(
                    f"runtime-{mode}",
                    policy=policy,
                    db_path=self.root / f"runtime-{mode}.sqlite3",
                )
                self.age_run(run)

                preflight = lambda: run.preflight_model_call(
                    call_id="runtime-preflight",
                    input_value={"context": "small"},
                    requested_route=run.envelope.assigned_route,
                    purpose="runtime budget test",
                )
                if mode == "enforce":
                    with self.assertRaisesRegex(
                        HARNESS.HarnessPolicyError,
                        "max_run_seconds",
                    ):
                        preflight()
                    with self.assertRaisesRegex(
                        HARNESS.HarnessPolicyError,
                        "max_run_seconds",
                    ):
                        run.complete({"test": "must remain running"})
                    self.assertEqual(
                        run.store.snapshot(run.run_id)["status"],
                        HARNESS.RunStatus.RUNNING.value,
                    )
                else:
                    preflight()
                    run.complete({"test": "shadow records but permits"})
                    self.assertEqual(
                        run.store.snapshot(run.run_id)["status"],
                        HARNESS.RunStatus.SUCCEEDED.value,
                    )

                events = self.budget_events(run)
                self.assertEqual(len(events), 2)
                self.assertTrue(
                    all(
                        "max_run_seconds" in event["payload"]["violations"]
                        for event in events
                    )
                )
                operations = {
                    event["payload"]["operation"]
                    for event in events
                }
                self.assertEqual(
                    operations,
                    {"model call", "run completion"},
                )
                self.assertTrue(run.store.verify_chain(run.run_id)["valid"])

    def test_tool_authorization_is_role_scoped_and_default_deny(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        soc = self.make_run(
            "soc-tool-policy",
            policy=policy,
            db_path=self.root / "soc-tool-policy.sqlite3",
        )
        elastic = soc.authorize_tool(
            round_number=1,
            query_id="elastic-allowed",
            backend="elastic",
        )
        self.assertTrue(elastic.allowed)
        self.assertFalse(elastic.requires_approval)

        live_osquery = soc.authorize_tool(
            round_number=1,
            query_id="osquery-unapproved",
            backend="osquery",
        )
        self.assertFalse(live_osquery.allowed)
        self.assertTrue(live_osquery.requires_approval)
        self.assertIn("human approval", live_osquery.reason)
        self.assertTrue(
            soc.authorize_tool(
                round_number=1,
                query_id="osquery-approved",
                backend="osquery",
                approved=True,
            ).allowed
        )

        unknown = soc.authorize_tool(
            round_number=1,
            query_id="unknown-default-deny",
            backend="shell",
            approved=True,
        )
        self.assertFalse(unknown.allowed)
        self.assertIn("not registered", unknown.reason)

        intel = self.make_run(
            "intel-tool-policy",
            policy=policy,
            db_path=self.root / "intel-tool-policy.sqlite3",
            role=HARNESS.AgentRole.CYBER_THREAT_INTEL.value,
        )
        role_denied = intel.authorize_tool(
            round_number=1,
            query_id="osquery-not-assigned",
            backend="osquery",
            approved=True,
        )
        self.assertFalse(role_denied.allowed)
        self.assertIn("not assigned", role_denied.reason)

        authorization_events = [
            event
            for event in soc.store.export_trace(soc.run_id)["events"]
            if event["event_type"] == "policy.tool-authorization"
        ]
        self.assertEqual(len(authorization_events), 4)
        unapproved_payload = next(
            event["payload"]
            for event in authorization_events
            if event["payload"]["query_id"] == "osquery-unapproved"
        )
        self.assertFalse(unapproved_payload["allowed"])
        self.assertTrue(unapproved_payload["requires_approval"])
        self.assertTrue(unapproved_payload["effective_in_shadow"])

    def test_query_round_records_result_semantics_and_rejected_proposals(
        self,
    ) -> None:
        run = self.make_run("query-result-semantics")
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "zero",
                        "backend": "elastic",
                        "purpose": "Prove an exact empty result.",
                    },
                    {
                        "query_id": "unknown",
                        "backend": "oql",
                        "purpose": "Exercise an omitted returned count.",
                    },
                    {
                        "query_id": "positive",
                        "backend": "pcap_zeek",
                        "purpose": "Exercise a positive bounded result.",
                    },
                ],
                "results": [
                    {
                        "query_id": "zero",
                        "backend": "elastic",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {"returned_rows": 0},
                    },
                    {
                        "query_id": "unknown",
                        "backend": "oql",
                        "status": "ok",
                        "evidence": {"window": "bounded"},
                    },
                    {
                        "query_id": "positive",
                        "backend": "pcap_zeek",
                        "status": "ok",
                        "read_only": True,
                        "evidence": {
                            "projection": {
                                "returned_hits": 3,
                                "source_truncated": True,
                            }
                        },
                    },
                    {
                        "query_id": "rejected",
                        "backend": "osquery",
                        "status": "rejected",
                        "read_only": True,
                        "error": "proposal rejected by policy",
                    },
                ],
            }
        )

        trace = run.store.export_trace(run.run_id)
        calls = {item["call_id"]: item for item in trace["tool_calls"]}
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls["round-1-zero"]["coverage"], "exact-zero")
        self.assertEqual(calls["round-1-zero"]["read_only"], 1)
        self.assertEqual(calls["round-1-unknown"]["coverage"], "unknown")
        self.assertEqual(calls["round-1-unknown"]["read_only"], 0)
        self.assertEqual(calls["round-1-positive"]["coverage"], "bounded-result")
        self.assertEqual(calls["round-1-positive"]["truncated"], 1)

        rejected = calls["round-1-rejected"]
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["coverage"], "evidence-gap")
        self.assertEqual(rejected["capability"], "endpoint.osquery.query")
        self.assertEqual(rejected["purpose"], "proposal rejected before execution")
        query_event = next(
            event
            for event in trace["events"]
            if event["event_type"] == "queries.completed"
        )
        self.assertEqual(query_event["payload"]["request_count"], 3)
        self.assertEqual(query_event["payload"]["result_count"], 4)
        self.assertEqual(query_event["payload"]["rejected_proposal_count"], 1)
        self.assertTrue(trace["integrity"]["valid"])

    def test_query_round_resolves_digest_bound_nested_status_in_partial_batch(
        self,
    ) -> None:
        run = self.make_run("query-partial-batch-semantics")
        query_digest_ok = "a" * 64
        result_digest_ok = "b" * 64
        query_digest_failed = "c" * 64
        result_digest_failed = "d" * 64
        query_digest_ok_two = "1" * 64
        result_digest_ok_two = "2" * 64
        query_digest_failed_two = "3" * 64
        result_digest_failed_two = "4" * 64
        batch_result = {
            "backend": "security_onion",
            "query_ids": [
                "successful-pivot",
                "failed-pivot",
                "successful-pivot-two",
                "failed-pivot-two",
            ],
            "status": "partial",
            "read_only": True,
            "security_onion_response_digest": "e" * 64,
            "evidence": {
                "complete": False,
                "partial": True,
                "read_only": True,
                "controls_valid": True,
                "results": [
                    {
                        "query_id": "successful-pivot",
                        "status": "ok",
                        "semantic_valid": True,
                        "query_digest": query_digest_ok,
                        "result_digest": result_digest_ok,
                        "returned_hits": 2,
                    },
                    {
                        "query_id": "failed-pivot",
                        "status": "invalid_response",
                        "semantic_valid": False,
                        "query_digest": query_digest_failed,
                        "result_digest": result_digest_failed,
                    },
                    {
                        "query_id": "successful-pivot-two",
                        "status": "ok",
                        "semantic_valid": True,
                        "query_digest": query_digest_ok_two,
                        "result_digest": result_digest_ok_two,
                        "returned_hits": 0,
                    },
                    {
                        "query_id": "failed-pivot-two",
                        "status": "invalid_response",
                        "semantic_valid": False,
                        "query_digest": query_digest_failed_two,
                        "result_digest": result_digest_failed_two,
                    },
                ],
            },
            "trusted_query_audit": [
                {
                    "query_id": "successful-pivot",
                    "status": "ok",
                    "semantic_valid": True,
                    "timed_out": False,
                    "query_digest": query_digest_ok,
                    "result_digest": result_digest_ok,
                    "returned_hits": 2,
                    "shards": {
                        "total": 4,
                        "successful": 4,
                        "skipped": 2,
                        "failed": 0,
                        "failures": [],
                    },
                },
                {
                    "query_id": "failed-pivot",
                    "status": "invalid_response",
                    "semantic_valid": False,
                    "timed_out": False,
                    "query_digest": query_digest_failed,
                    "result_digest": result_digest_failed,
                    "shards": {
                        "total": 0,
                        "successful": 0,
                        "skipped": 0,
                        "failed": 0,
                        "failures": [],
                    },
                },
                {
                    "query_id": "successful-pivot-two",
                    "status": "ok",
                    "semantic_valid": True,
                    "timed_out": False,
                    "query_digest": query_digest_ok_two,
                    "result_digest": result_digest_ok_two,
                    "returned_hits": 0,
                    "shards": {
                        "total": 2,
                        "successful": 2,
                        "skipped": 0,
                        "failed": 0,
                        "failures": [],
                    },
                },
                {
                    "query_id": "failed-pivot-two",
                    "status": "invalid_response",
                    "semantic_valid": False,
                    "timed_out": False,
                    "query_digest": query_digest_failed_two,
                    "result_digest": result_digest_failed_two,
                    "shards": {
                        "total": 0,
                        "successful": 0,
                        "skipped": 0,
                        "failed": 0,
                        "failures": [],
                    },
                },
            ],
        }
        run.query_round(
            {
                "round": 1,
                "requests": [
                    {
                        "query_id": "successful-pivot",
                        "backend": "elastic",
                        "purpose": "Validate the exact network event.",
                    },
                    {
                        "query_id": "failed-pivot",
                        "backend": "elastic",
                        "purpose": "Test a second discriminator.",
                    },
                    {
                        "query_id": "successful-pivot-two",
                        "backend": "elastic",
                        "purpose": "Measure exact prevalence.",
                    },
                    {
                        "query_id": "failed-pivot-two",
                        "backend": "elastic",
                        "purpose": "Test an unsupported field response.",
                    },
                ],
                "results": [batch_result],
            }
        )

        calls = {
            item["call_id"]: item
            for item in run.store.export_trace(run.run_id)["tool_calls"]
        }
        successful = calls["round-1-successful-pivot"]
        failed = calls["round-1-failed-pivot"]
        successful_two = calls["round-1-successful-pivot-two"]
        failed_two = calls["round-1-failed-pivot-two"]
        self.assertEqual(successful["status"], "ok")
        self.assertEqual(successful["coverage"], "bounded-result")
        self.assertEqual(successful["truncated"], 0)
        self.assertEqual(failed["status"], "invalid_response")
        self.assertEqual(failed["coverage"], "evidence-gap")
        self.assertEqual(successful_two["status"], "ok")
        self.assertEqual(successful_two["coverage"], "exact-zero")
        self.assertEqual(failed_two["status"], "invalid_response")
        self.assertEqual(
            successful["result_digest"],
            HARNESS.digest_json(batch_result),
        )
        self.assertEqual(failed["result_digest"], successful["result_digest"])
        self.assertEqual(
            successful_two["result_digest"],
            successful["result_digest"],
        )
        self.assertEqual(failed_two["result_digest"], successful["result_digest"])

        mismatched = json.loads(json.dumps(batch_result))
        mismatched["trusted_query_audit"][0]["result_digest"] = "f" * 64
        status, observation = HARNESS.resolve_query_binding(
            mismatched,
            "successful-pivot",
        )
        self.assertEqual(status, "partial")
        self.assertIs(observation, mismatched)

        malformed_cases = []

        def malformed(label, mutate):
            candidate = json.loads(json.dumps(batch_result))
            mutate(candidate)
            malformed_cases.append((label, candidate))

        malformed(
            "model evidence is not read-only",
            lambda item: item["evidence"].__setitem__("read_only", False),
        )
        malformed(
            "partial flag is inconsistent",
            lambda item: item["evidence"].__setitem__("partial", False),
        )
        malformed(
            "complete flag is inconsistent",
            lambda item: item["evidence"].__setitem__("complete", True),
        )
        malformed(
            "controls are invalid",
            lambda item: item["evidence"].__setitem__(
                "controls_valid",
                False,
            ),
        )
        malformed(
            "response digest is malformed",
            lambda item: item.__setitem__(
                "security_onion_response_digest",
                "not-a-digest",
            ),
        )
        malformed(
            "outer query ids are duplicated",
            lambda item: item["query_ids"].append("successful-pivot"),
        )
        malformed(
            "nested query coverage is incomplete",
            lambda item: item["evidence"]["results"].pop(),
        )
        malformed(
            "audit query coverage is incomplete",
            lambda item: item["trusted_query_audit"].pop(),
        )
        malformed(
            "nested status is outside the closed broker contract",
            lambda item: (
                item["evidence"]["results"][0].__setitem__(
                    "status",
                    "unknown",
                ),
                item["evidence"]["results"][0].__setitem__(
                    "semantic_valid",
                    False,
                ),
                item["trusted_query_audit"][0].__setitem__(
                    "status",
                    "unknown",
                ),
                item["trusted_query_audit"][0].__setitem__(
                    "semantic_valid",
                    False,
                ),
            ),
        )
        malformed(
            "semantic validity contradicts success",
            lambda item: item["evidence"]["results"][0].__setitem__(
                "semantic_valid",
                False,
            ),
        )
        malformed(
            "successful query timed out",
            lambda item: item["trusted_query_audit"][0].__setitem__(
                "timed_out",
                True,
            ),
        )
        malformed(
            "successful shard coverage is incomplete",
            lambda item: item["trusted_query_audit"][0]["shards"].__setitem__(
                "successful",
                3,
            ),
        )
        malformed(
            "successful shard count is zero",
            lambda item: (
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "total",
                    0,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "successful",
                    0,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "skipped",
                    0,
                ),
            ),
        )
        malformed(
            "successful query has failed shards",
            lambda item: (
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "failed",
                    1,
                ),
                item["trusted_query_audit"][0]["shards"].__setitem__(
                    "failures",
                    [{"reason": "synthetic"}],
                ),
            ),
        )
        for label, candidate in malformed_cases:
            with self.subTest(label=label):
                status, _observation = HARNESS.resolve_query_binding(
                    candidate,
                    "successful-pivot",
                )
                self.assertEqual(status, "partial")

        ordinary = {
            "query_id": "ordinary",
            "backend": "elastic",
            "status": "ok",
            "read_only": True,
        }
        status, observation = HARNESS.resolve_query_binding(
            ordinary,
            "ordinary",
        )
        self.assertEqual(status, "ok")
        self.assertIs(observation, ordinary)

    def test_changed_evidence_manifest_can_be_recatalogued_idempotently(
        self,
    ) -> None:
        run = self.make_run("recatalogue-run")
        original = self.prompt_package()
        self.assertEqual(run.catalogue_prompt_evidence(original), 2)

        changed = json.loads(json.dumps(original))
        changed["evidence_reference_contract"]["references"].append(
            {
                "ref": "elastic:event-99",
                "source": "security-onion-events",
                "source_class": "elastic_event",
                "status": "available",
                "returned": 1,
                "corroborating": True,
            }
        )
        self.assertEqual(run.catalogue_prompt_evidence(changed), 3)
        self.assertEqual(run.catalogue_prompt_evidence(changed), 3)

        trace = run.store.export_trace(run.run_id)
        catalogue_events = [
            event
            for event in trace["events"]
            if event["event_type"] == "evidence.catalogued"
        ]
        self.assertEqual(len(catalogue_events), 2)
        self.assertEqual(
            len(
                {
                    event["payload"]["manifest_digest"]
                    for event in catalogue_events
                }
            ),
            2,
        )
        self.assertEqual(len(trace["evidence"]), 3)
        self.assertTrue(trace["integrity"]["valid"])

    def test_run_identity_is_bound_to_exact_policy_digest(self) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        run = self.make_run("policy-bound-run", policy=policy)
        self.assertEqual(
            run.store.snapshot(run.run_id)["policy_digest"],
            policy.digest,
        )
        changed_policy = dataclasses.replace(
            policy,
            budgets={
                **policy.budgets,
                "max_model_calls": policy.budgets["max_model_calls"] + 1,
            },
        )
        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "different job or policy",
        ):
            HARNESS.HarnessRun(
                run.store,
                self.envelope(run.run_id),
                changed_policy,
            )

    def test_preflight_and_tool_approval_replay_without_collision(self) -> None:
        run = self.make_run("approval-replay-run")
        run.preflight_model_call(
            call_id="stable-model-call",
            input_value={"rows": [{"id": 1}]},
            requested_route=run.envelope.assigned_route,
            purpose="stable replay test",
        )
        run.preflight_model_call(
            call_id="stable-model-call",
            input_value={"rows": [{"id": 1}]},
            requested_route=run.envelope.assigned_route,
            purpose="stable replay test",
        )
        denied = run.authorize_tool(
            round_number=1,
            query_id="live-host-query",
            backend="osquery",
        )
        approved = run.authorize_tool(
            round_number=1,
            query_id="live-host-query",
            backend="osquery",
            approved=True,
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(approved.allowed)
        trace = run.store.export_trace(run.run_id)
        self.assertEqual(
            sum(
                event["event_type"] == "policy.budget"
                for event in trace["events"]
            ),
            1,
        )
        self.assertEqual(
            sum(
                event["event_type"] == "policy.tool-authorization"
                for event in trace["events"]
            ),
            2,
        )
        self.assertTrue(trace["integrity"]["valid"])

    def test_hypothesis_provenance_demotes_unsupported_claims(self) -> None:
        run = self.make_run("hypothesis-run")
        run.catalogue_prompt_evidence(self.prompt_package())
        result = run.store.record_hypotheses(
            run.run_id,
            [
                {
                    "id": "known",
                    "statement": "Known evidence supports this.",
                    "status": "supported",
                    "supporting_evidence": ["alert:42"],
                },
                {
                    "id": "unknown",
                    "statement": "Unknown evidence cannot support this.",
                    "status": "supported",
                    "supporting_evidence": ["fabricated:ref"],
                },
                "invalid",
            ],
            revision=1,
        )
        self.assertEqual(result, {"accepted": 2, "rejected": 1})
        statuses = {
            item["hypothesis_id"]: item["status"]
            for item in run.store.export_trace(run.run_id)["hypotheses"]
        }
        self.assertEqual(statuses, {"known": "supported", "unknown": "unresolved"})

    def test_hypothesis_revision_collision_is_rejected_and_secrets_are_redacted(
        self,
    ) -> None:
        run = self.make_run("hypothesis-collision-run")
        run.catalogue_prompt_evidence(self.prompt_package())
        hypothesis = {
            "id": "credential-lead",
            "statement": "Observed password=do-not-store-this",
            "status": "supported",
            "supporting_evidence": ["alert:42"],
            "next_discriminator": (
                "Use Bearer abcdefghijklmnopqrstuvwxyz0123456789 to pivot"
            ),
        }
        self.assertEqual(
            run.store.record_hypotheses(
                run.run_id,
                [hypothesis],
                revision=1,
            ),
            {"accepted": 1, "rejected": 0},
        )
        self.assertEqual(
            run.store.record_hypotheses(
                run.run_id,
                [hypothesis],
                revision=1,
            ),
            {"accepted": 1, "rejected": 0},
        )

        with self.assertRaisesRegex(
            HARNESS.HarnessIntegrityError,
            "revision collides with different content",
        ):
            run.store.record_hypotheses(
                run.run_id,
                [
                    {
                        **hypothesis,
                        "statement": "A materially different safe hypothesis.",
                    }
                ],
                revision=1,
            )

        trace = run.store.export_trace(run.run_id)
        stored = trace["hypotheses"][0]
        self.assertEqual(stored["statement"], "[redacted-sensitive-value]")
        self.assertEqual(
            stored["next_discriminator"],
            "[redacted-sensitive-value]",
        )
        serialized = json.dumps(trace, sort_keys=True)
        self.assertNotIn("do-not-store-this", serialized)
        self.assertNotIn(
            "abcdefghijklmnopqrstuvwxyz0123456789",
            serialized,
        )
        self.assertEqual(
            sum(
                event["event_type"] == "hypotheses.updated"
                for event in trace["events"]
            ),
            1,
        )
        self.assertTrue(trace["integrity"]["valid"])

    def test_memory_promotion_requires_clean_provenance_confidence_and_review(
        self,
    ) -> None:
        policy = HARNESS.HarnessPolicy.from_dict(self.policy_document())
        role = HARNESS.AgentRole.SOC_ANALYST.value
        valid = self.response()

        blocked = {
            **valid,
            "_automation_controls": {
                "memory_writeback_blocked": True,
                "reason": "untrusted prompt injection content",
            },
        }
        self.assertFalse(
            HARNESS.memory_promotion_decision(
                policy,
                blocked,
                role=role,
                has_shared_candidates=False,
            ).allowed
        )

        invalid_refs = {
            **valid,
            "_evidence_reference_validation": {
                **valid["_evidence_reference_validation"],
                "invalid_refs": ["fabricated:ref"],
            },
        }
        self.assertIn(
            "unresolved evidence",
            HARNESS.memory_promotion_decision(
                policy,
                invalid_refs,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        one_source = {
            **valid,
            "_evidence_reference_validation": {
                "invalid_refs": [],
                "corroborating_source_classes": ["suricata_alert"],
            },
        }
        self.assertIn(
            "fewer than two",
            HARNESS.memory_promotion_decision(
                policy,
                one_source,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        low_confidence = {**valid, "confidence": "medium", "confidence_score": 0.79}
        self.assertIn(
            "confidence",
            HARNESS.memory_promotion_decision(
                policy,
                low_confidence,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        no_review = {**valid, "_second_opinion": {"status": "not-run"}}
        self.assertIn(
            "reviewer",
            HARNESS.memory_promotion_decision(
                policy,
                no_review,
                role=role,
                has_shared_candidates=False,
            ).reason,
        )

        needs_approval = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=False,
        )
        self.assertFalse(needs_approval.allowed)
        self.assertTrue(needs_approval.requires_approval)

        shared_needs_approval = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=True,
        )
        self.assertFalse(shared_needs_approval.allowed)
        self.assertTrue(shared_needs_approval.requires_approval)
        self.assertIn("shared memory", shared_needs_approval.reason)

        approved = HARNESS.memory_promotion_decision(
            policy,
            valid,
            role=role,
            has_shared_candidates=True,
            human_approved=True,
        )
        self.assertTrue(approved.allowed)
        self.assertTrue(approved.requires_approval)


if __name__ == "__main__":
    unittest.main()
