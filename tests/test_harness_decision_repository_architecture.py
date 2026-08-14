from __future__ import annotations

import contextlib
import inspect
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import onion_sentinel_harness as harness
import harness_store_decision_persistence as decision_owner
import harness_store_hypothesis_persistence as hypothesis_owner


class AuditObservingStore(harness.HarnessStore):
    def __init__(self, path):
        self.audit_observations = []
        super().__init__(path)

    def _audit_event(self, event):
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            decision_count = connection.execute(
                "SELECT COUNT(*) FROM harness_decisions"
            ).fetchone()[0]
            hypothesis_count = connection.execute(
                "SELECT COUNT(*) FROM harness_hypotheses"
            ).fetchone()[0]
        self.audit_observations.append(
            (event["event_type"], decision_count, hypothesis_count)
        )


class HarnessDecisionRepositoryArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "harness.sqlite3"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def policy() -> harness.HarnessPolicy:
        return harness.HarnessPolicy.from_dict(
            {
                "schema": harness.POLICY_SCHEMA,
                "version": "arr-192-characterization",
                "enabled": True,
                "mode": "shadow",
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

    @staticmethod
    def envelope(run_id: str) -> harness.JobEnvelope:
        return harness.JobEnvelope.from_prompt(
            run_id=run_id,
            prompt_package={
                "alert": {"alert_id": "alert-42", "rule_name": "Synthetic"},
                "group_id": "group-42",
            },
            role="soc-analyst",
            assigned_route="codex-cli:gpt-5.6-sol:high",
            configuration={
                "query_mode": "read-only",
                "max_rounds": 3,
                "reviewer_route": "codex-cli:gpt-5.6-terra:high",
            },
            source_revision="1" * 40,
            policy_version="arr-192-characterization",
        )

    def make_run(self, run_id="decision-run", store_type=harness.HarnessStore):
        store = store_type(self.db_path)
        return harness.HarnessRun(store, self.envelope(run_id), self.policy())

    def test_public_signatures_are_stable(self) -> None:
        repository = harness.HarnessStoreDecisionRepository
        self.assertEqual(
            str(inspect.signature(repository.record_hypotheses)),
            "(self, run_id: 'str', hypotheses: 'Any', *, revision: 'int') -> 'dict[str, int]'",
        )
        self.assertEqual(
            str(inspect.signature(repository.record_decision)),
            "(self, run_id: 'str', *, decision_id: 'str', decision_type: 'str', response: 'Mapping[str, Any]', stage: 'str' = 'evidence-synthesis') -> 'None'",
        )

    def test_inward_owners_do_not_import_facade(self) -> None:
        for owner in (decision_owner, hypothesis_owner):
            source = inspect.getsource(owner)
            self.assertNotIn("import harness_store_decision_repository", source)
            self.assertNotIn("from harness_store_decision_repository", source)
        repository = harness.HarnessStoreDecisionRepository
        self.assertLessEqual(
            len(inspect.getsource(repository.record_hypotheses).splitlines()),
            20,
        )
        self.assertLessEqual(
            len(inspect.getsource(repository.record_decision).splitlines()),
            25,
        )

    def test_hypothesis_normalization_provenance_and_revision_guards(self) -> None:
        run = self.make_run("hypothesis-characterization")
        run.store.register_evidence(
            run.run_id,
            evidence_ref="alert:42",
            source="security-onion-alert",
            source_class="suricata_alert",
            trust_tier=harness.TrustTier.TRUSTED_COLLECTOR.value,
            corroborating=True,
            status="available",
            metadata={"returned": 1},
        )
        items = [
            {
                "id": " supported id ",
                "statement": "Known evidence supports this.",
                "status": "supported",
                "supporting_evidence": ["alert:42", "unknown:ignored"],
                "next_discriminator": "Collect endpoint evidence.",
            },
            {
                "id": "unsupported",
                "statement": "Unknown evidence cannot support this.",
                "status": "supported",
                "supporting_evidence": ["fabricated:ref"],
            },
            {"id": "invalid-status", "statement": "Present", "status": "wrong"},
            "invalid",
        ]
        self.assertEqual(
            run.store.record_hypotheses(run.run_id, items, revision=2),
            {"accepted": 2, "rejected": 2},
        )
        trace = run.store.export_trace(run.run_id)
        observed = {row["hypothesis_id"]: row for row in trace["hypotheses"]}
        self.assertEqual(set(observed), {"supported-id", "unsupported"})
        self.assertEqual(observed["supported-id"]["status"], "supported")
        self.assertEqual(
            json.loads(observed["supported-id"]["supporting_refs_json"]),
            ["alert:42"],
        )
        self.assertEqual(observed["unsupported"]["status"], "unresolved")
        with self.assertRaisesRegex(
            harness.HarnessIntegrityError,
            "revision cannot move backwards",
        ):
            run.store.record_hypotheses(run.run_id, items[:1], revision=1)
        with self.assertRaisesRegex(
            harness.HarnessIntegrityError,
            "revision collides with different content",
        ):
            run.store.record_hypotheses(
                run.run_id,
                [{**items[0], "statement": "Changed"}],
                revision=2,
            )

    def test_non_list_hypotheses_are_side_effect_free(self) -> None:
        run = self.make_run("non-list-hypotheses")
        before = run.store.export_trace(run.run_id)
        self.assertEqual(
            run.store.record_hypotheses(run.run_id, {"not": "a list"}, revision=1),
            {"accepted": 0, "rejected": 0},
        )
        after = run.store.export_trace(run.run_id)
        self.assertEqual(after["events"], before["events"])
        self.assertEqual(after["hypotheses"], [])

    def test_decision_projection_replay_collision_and_invalid_confidence(self) -> None:
        run = self.make_run("decision-characterization")
        response = {
            "event_status": "observed",
            "detection_outcome": "true_positive_suspicious",
            "final_disposition_status": "reviewed",
            "confidence": "high",
            "confidence_score": float("inf"),
            "executive_summary": "Summary",
            "detection_outcome_reasoning": "Reasoning",
            "tuning_reason": "Tuning",
            "evidence_used": ["alert:42", "zeek:uid-42"],
            "unselected_private_field": "still-bound-by-response-digest",
        }
        kwargs = {
            "decision_id": "decision-1",
            "decision_type": "alert-triage",
            "response": response,
            "stage": harness.Stage.EVIDENCE_SYNTHESIS.value,
        }
        run.store.record_decision(run.run_id, **kwargs)
        run.store.record_decision(run.run_id, **kwargs)
        trace = run.store.export_trace(run.run_id)
        self.assertEqual(len(trace["decisions"]), 1)
        self.assertEqual(
            sum(event["event_type"] == "decision.recorded" for event in trace["events"]),
            1,
        )
        decision = trace["decisions"][0]
        self.assertIsNone(decision["confidence_score"])
        self.assertEqual(json.loads(decision["evidence_refs_json"]), response["evidence_used"])
        payload = json.loads(decision["payload_json"])
        self.assertEqual(payload["response_digest"], harness.digest_json(response))
        with self.assertRaisesRegex(
            harness.HarnessIntegrityError,
            "decision_id collides with different decision content",
        ):
            run.store.record_decision(
                run.run_id,
                **{**kwargs, "response": {**response, "detection_outcome": "benign"}},
            )
        with self.assertRaisesRegex(harness.HarnessPolicyError, "invalid decision stage"):
            run.store.record_decision(run.run_id, **{**kwargs, "stage": "invalid"})

    def test_transactions_commit_before_audit(self) -> None:
        run = self.make_run("audit-order", AuditObservingStore)
        run.store.record_hypotheses(
            run.run_id,
            [{"id": "h-1", "statement": "Unresolved", "status": "unresolved"}],
            revision=1,
        )
        run.store.record_decision(
            run.run_id,
            decision_id="d-1",
            decision_type="alert-triage",
            response={"detection_outcome": "unknown", "confidence_score": 0.5},
        )
        self.assertEqual(
            run.store.audit_observations[-2:],
            [("hypotheses.updated", 0, 1), ("decision.recorded", 1, 1)],
        )


if __name__ == "__main__":
    unittest.main()
