from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import round_admission


class QueryRoundAdmissionPackageTests(unittest.TestCase):
    class ContractError(ValueError):
        pass

    def setUp(self):
        self.available = True
        self.authorization = round_admission.Authorization(True)
        self.repair = None
        self.ignored = []

    def dependencies(self):
        def normalize(raw, **_kwargs):
            if raw.get("invalid"):
                raise self.ContractError("malformed request")
            return copy.deepcopy(raw)

        return round_admission.Dependencies(
            normalize=normalize,
            validate_repair=lambda request, scope: (
                None
                if request["backend"] == scope["backend"]
                else (_ for _ in ()).throw(self.ContractError("repair widened scope"))
            ),
            backend_available=lambda _backend: self.available,
            semantic_digest=lambda request: request.get("digest", request["query_id"]),
            ignore_semantic_repeat=lambda state: self.ignored.append(state) or state + 1,
            authorize=lambda _request: self.authorization,
            repair_scope=lambda _raw, **_kwargs: copy.deepcopy(self.repair),
            query_text=lambda value, limit: str(value or "").strip()[:limit],
            valid_query_id=lambda value: bool(value) and " " not in value,
        )

    def invoke(self, requests, **overrides):
        values = {
            "state": 10,
            "round_number": 2,
            "repair_round": False,
            "pending_repair_scopes": {},
            "seen_semantic_digests": set(),
            "time_envelope": {"start": "a", "end": "b"},
            "authorization_context": {"anchor": {}},
            "dependencies": self.dependencies(),
            "error_type": self.ContractError,
        }
        values.update(overrides)
        return round_admission.run(requests, **values)

    def request(self, query_id="q-1", backend="elastic", digest="digest-1"):
        return {"query_id": query_id, "backend": backend, "digest": digest}

    def test_authorized_request_is_normalized_without_mutating_inputs(self):
        raw = [self.request()]
        snapshot = copy.deepcopy(raw)
        result = self.invoke(raw)
        self.assertEqual(result.normalized[0]["query_id"], "q-1")
        self.assertEqual(result.seen_semantic_digests, frozenset({"digest-1"}))
        self.assertEqual(raw, snapshot)

    def test_backend_unavailable_and_authorization_denial_fail_closed(self):
        self.available = False
        unavailable = self.invoke([self.request()])
        self.assertIn("backend is disabled", unavailable.rejected[0]["error"])
        self.assertEqual(unavailable.normalized, ())

        self.available = True
        self.authorization = round_admission.Authorization(
            False, "endpoint_live_query", "operator approval absent"
        )
        denied = self.invoke([self.request()])
        self.assertIn("endpoint_live_query", denied.rejected[0]["error"])
        self.assertEqual(denied.seen_semantic_digests, frozenset())

    def test_harness_decision_resolution_fails_closed_only_when_required(self):
        effective = lambda _mode, decision: bool(decision.allowed)
        self.assertTrue(round_admission.resolve_authorization(
            runtime_present=False, approval_gated=True, policy_mode="enforce",
            decision=None, decision_effective=effective,
            fallback_capability="endpoint_live_query",
        ).allowed)
        missing = round_admission.resolve_authorization(
            runtime_present=True, approval_gated=True, policy_mode="shadow",
            decision=None, decision_effective=effective,
            fallback_capability="endpoint_live_query",
        )
        self.assertFalse(missing.allowed)
        self.assertIn("unavailable", missing.reason)
        self.assertTrue(round_admission.resolve_authorization(
            runtime_present=True, approval_gated=False, policy_mode="enforce",
            decision=None, decision_effective=effective,
            fallback_capability="query",
        ).allowed)

        class Decision:
            allowed = False
            capability = "security_onion_query"
            reason = "policy denied"

        denied = round_admission.resolve_authorization(
            runtime_present=True, approval_gated=False, policy_mode="enforce",
            decision=Decision(), decision_effective=effective,
            fallback_capability="query",
        )
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.capability, "security_onion_query")

    def test_semantic_repeat_is_rejected_and_updates_opaque_state(self):
        result = self.invoke(
            [self.request()], seen_semantic_digests={"digest-1"}
        )
        self.assertEqual(result.state, 11)
        self.assertEqual(self.ignored, [10])
        self.assertEqual(
            result.rejected[0]["request_semantic_digest"], "digest-1"
        )

    def test_duplicate_normal_ids_are_renamed_but_repairs_fail_closed(self):
        normal = self.invoke([
            self.request("same", digest="first"),
            self.request("same", digest="second"),
        ])
        self.assertEqual(normal.normalized[1]["query_id"], "round-2-query-2")

        scope = {"query_id": "same", "backend": "elastic"}
        repair = self.invoke(
            [self.request("same", digest="first"), self.request("same", digest="second")],
            repair_round=True,
            pending_repair_scopes={"same": scope},
        )
        self.assertEqual(len(repair.normalized), 1)
        self.assertEqual(repair.rejected[0]["backend"], "contract")

    def test_contract_failure_gets_stable_id_and_bounded_repair_candidate(self):
        self.repair = {"query_id": "repair-1", "backend": "elastic"}
        result = self.invoke([{
            "query_id": "bad id", "backend": "elastic", "invalid": True
        }])
        self.assertEqual(result.rejected[0]["query_id"], "round-2-query-1")
        self.assertEqual(result.rejected[0]["error"], "malformed request")
        self.assertEqual(
            result.repair_scopes["repair-1"]["trigger"], "contract_rejection"
        )

    def test_repair_must_match_pending_query_and_cannot_schedule_another_repair(self):
        self.repair = {"query_id": "new", "backend": "elastic"}
        result = self.invoke(
            [self.request("unexpected")],
            repair_round=True,
            pending_repair_scopes={"expected": {
                "query_id": "expected", "backend": "elastic"
            }},
        )
        self.assertIn("unrequested query_id", result.rejected[0]["error"])
        self.assertEqual(result.repair_scopes, {})


if __name__ == "__main__":
    unittest.main()
