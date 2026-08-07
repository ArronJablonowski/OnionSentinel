from __future__ import annotations

from dataclasses import dataclass
import unittest

from n8n.onion_sentinel.analysis.persistence.memory_policy import (
    MemoryGuardPolicy,
    MemoryGuardPorts,
    apply_memory_guards,
)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    requires_approval: bool
    reason: str


class MemoryPromotionPolicyTests(unittest.TestCase):
    def ports(
        self,
        audits: list[dict],
        *,
        decision: Decision | None = None,
    ) -> MemoryGuardPorts:
        return MemoryGuardPorts(
            promotion_decision=(
                (lambda _response, _shared: decision)
                if decision is not None else None
            ),
            decision_is_effective=lambda value: bool(value.allowed),
            record_audit=audits.append,
            apply_freeze=lambda allowed, reason, frozen: (
                (False, "evaluation memory freeze")
                if frozen else (allowed, reason)
            ),
            plan=lambda candidates, allowed, reason: {
                "count": len(candidates), "allowed": allowed, "reason": reason,
            },
            reviewer_eligibility=lambda _value: (True, "reviewer eligible"),
            controlled_claim_digest=lambda value: f"claim:{value['job_id']}",
        )

    def test_denied_harness_policy_blocks_primary_and_reviewer(self) -> None:
        audits: list[dict] = []
        response = {
            "memory_candidates": [{"scope": "shared"}],
            "_second_opinion": {
                "response": {"memory_candidates": [{"scope": "agent"}]}
            },
        }
        result = apply_memory_guards(
            response,
            policy=MemoryGuardPolicy(False, {"job_id": "job-1"}),
            ports=self.ports(
                audits,
                decision=Decision(False, True, "human approval required"),
            ),
        )
        self.assertFalse(result.primary_allowed)
        self.assertFalse(result.reviewer_allowed)
        self.assertEqual(result.reviewer_reason, "human approval required")
        self.assertTrue(response["_automation_controls"]["requires_human_review"])
        self.assertEqual(response["_analysis_controlled_claim_sha256"], "claim:job-1")
        self.assertEqual(audits[0]["candidate_count"], 2)

    def test_evaluation_freeze_overrides_otherwise_eligible_lanes(self) -> None:
        response = {
            "memory_candidates": [{"scope": "agent"}],
            "_second_opinion": {
                "response": {"memory_candidates": [{"scope": "agent"}]}
            },
        }
        result = apply_memory_guards(
            response,
            policy=MemoryGuardPolicy(True, None),
            ports=self.ports([], decision=Decision(True, False, "allowed")),
        )
        self.assertFalse(result.primary_allowed)
        self.assertFalse(result.reviewer_allowed)
        self.assertEqual(result.primary_reason, "evaluation memory freeze")
        self.assertTrue(response["_analysis_evaluation_memory_frozen"])

    def test_absent_harness_does_not_record_policy_audit(self) -> None:
        audits: list[dict] = []
        response: dict = {}
        result = apply_memory_guards(
            response,
            policy=MemoryGuardPolicy(False, None),
            ports=self.ports(audits),
        )
        self.assertEqual(audits, [])
        self.assertEqual(result.primary_candidates, [])
        self.assertTrue(result.primary_allowed)
        self.assertEqual(response["_memory_writeback"]["count"], 0)

    def test_harness_with_no_candidates_records_explicit_empty_audit(self) -> None:
        audits: list[dict] = []
        apply_memory_guards(
            {},
            policy=MemoryGuardPolicy(False, None),
            ports=self.ports(audits, decision=Decision(True, False, "unused")),
        )
        self.assertEqual(audits[0]["reason"], "no memory candidates")
        self.assertEqual(audits[0]["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
