from __future__ import annotations

import importlib
import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

FOUNDATION = importlib.import_module("harness_run_foundation")
PREFLIGHT = importlib.import_module("harness_run_model_preflight")


class FakeStore:
    def __init__(self, reservation=None):
        self.calls = []
        self.reservation = reservation or {
            "reserved": True,
            "total": 1,
            "operation_count": 1,
            "violations": [],
        }

    def append_event(self, run_id, event_type, stage, payload, **kwargs):
        self.calls.append(
            ("append_event", run_id, event_type, stage, payload, kwargs)
        )

    def reserve_budget_operation(self, run_id, **kwargs):
        self.calls.append(("reserve_budget_operation", run_id, kwargs))
        return dict(self.reservation)


class SyntheticFoundation(FOUNDATION.HarnessRunFoundation):
    def __init__(
        self,
        *,
        mode="shadow",
        primary_route="codex-cli:gpt-5.6-sol:high",
        reviewer_route="codex-cli:gpt-5.6-terra:high",
        reservation=None,
        elapsed_seconds=12.5,
    ):
        self.store = FakeStore(reservation)
        self.envelope = SimpleNamespace(
            run_id="run-1",
            assigned_route=primary_route,
            assigned_reviewer_route=reviewer_route,
        )
        self.policy = SimpleNamespace(
            mode=mode,
            budgets={
                "max_model_calls": 4,
                "max_prompt_evidence_bytes": 1_000,
                "max_prompt_evidence_rows": 10,
                "max_run_seconds": 60,
            },
        )
        self._model_calls = 0
        self.elapsed_seconds = elapsed_seconds

    def _elapsed_seconds(self):
        return self.elapsed_seconds


class HarnessModelPreflightArchitectureTests(unittest.TestCase):
    def test_inward_owner_does_not_import_facade(self) -> None:
        source = inspect.getsource(PREFLIGHT)
        self.assertNotIn("import harness_run_foundation", source)
        self.assertNotIn("from harness_run_foundation", source)
        facade_source = inspect.getsource(
            FOUNDATION.HarnessRunFoundation.preflight_model_call
        )
        self.assertLessEqual(len(facade_source.splitlines()), 30)

    def test_stable_surface_and_signatures(self) -> None:
        self.assertEqual(
            str(
                inspect.signature(
                    FOUNDATION.HarnessRunFoundation.preflight_model_call
                )
            ),
            "(self, *, call_id: 'str', input_value: 'Any', requested_route: 'str', purpose: 'str', independent_review: 'bool' = False) -> 'None'",
        )
        self.assertEqual(
            str(inspect.signature(FOUNDATION.HarnessRunFoundation._enforce_budget)),
            "(self, *, operation_id: 'str', operation: 'str', stage: 'str', observed: 'Mapping[str, Any]', violations: 'Sequence[str]') -> 'None'",
        )

    def test_primary_preflight_preserves_route_reservation_budget_event_order(self) -> None:
        run = SyntheticFoundation()
        input_value = {"rows": [{"id": 1}, {"id": 2}], "context": "safe"}
        route = run.envelope.assigned_route
        run.preflight_model_call(
            call_id="primary-1",
            input_value=input_value,
            requested_route=route,
            purpose="primary analysis",
        )
        self.assertEqual(
            [call[0] for call in run.store.calls],
            ["append_event", "reserve_budget_operation", "append_event"],
        )
        route_event = run.store.calls[0]
        self.assertEqual(route_event[2:4], ("policy.model-route", "primary-analysis"))
        self.assertEqual(
            route_event[4],
            {
                "call_id": "primary-1",
                "purpose": "primary analysis",
                "requested_route": route,
                "expected_route": route,
                "independent_review": False,
                "allowed": True,
                "reason": "requested route matches the immutable primary assignment",
                "policy_mode": "shadow",
            },
        )
        self.assertEqual(
            route_event[5],
            {"idempotency_key": "policy.model-route:primary-1"},
        )
        reservation = run.store.calls[1][2]
        self.assertEqual(
            reservation,
            {
                "reservation_type": "model-call",
                "reservation_id": "primary-1",
                "amount": 1,
                "max_total": 4,
                "max_operations": 4,
                "enforce": False,
                "preexisting_violations": [],
            },
        )
        budget_event = run.store.calls[2]
        self.assertEqual(budget_event[2:4], ("policy.budget", "primary-analysis"))
        self.assertEqual(
            budget_event[4]["observed"],
            {
                "call_id": "primary-1",
                "purpose": "primary analysis",
                "requested_route": route,
                "expected_route": route,
                "route_allowed": True,
                "independent_review": False,
                "next_model_call": 1,
                "prompt_bytes": len(
                    FOUNDATION.canonical_json(input_value).encode("utf-8")
                ),
                "approximate_evidence_rows": 2,
                "reserved": True,
            },
        )
        self.assertEqual(budget_event[4]["violations"], [])
        self.assertEqual(run._model_calls, 1)

    def test_missing_reviewer_assignment_refuses_before_measurement_and_reservation(self) -> None:
        run = SyntheticFoundation(mode="enforce", reviewer_route="")
        with self.assertRaisesRegex(
            FOUNDATION.HarnessPolicyError,
            "no reviewer route was assigned",
        ):
            run.preflight_model_call(
                call_id="reviewer-1",
                input_value={"rows": [1]},
                requested_route="codex-cli:gpt-5.6-terra:high",
                purpose="independent review",
                independent_review=True,
            )
        self.assertEqual([call[0] for call in run.store.calls], ["append_event"])
        self.assertFalse(run.store.calls[0][4]["allowed"])
        self.assertEqual(run.store.calls[0][3], "independent-review")

    def test_shadow_route_mismatch_still_reserves_and_records_budget_decision(self) -> None:
        run = SyntheticFoundation(mode="shadow")
        run.preflight_model_call(
            call_id="shadow-mismatch",
            input_value={},
            requested_route="ollama:unexpected",
            purpose="shadow route audit",
        )
        self.assertEqual(
            [call[0] for call in run.store.calls],
            ["append_event", "reserve_budget_operation", "append_event"],
        )
        self.assertFalse(run.store.calls[0][4]["allowed"])
        self.assertEqual(
            run.store.calls[0][4]["reason"],
            "requested route does not match the immutable run assignment",
        )
        self.assertFalse(run.store.calls[2][4]["observed"]["route_allowed"])

    def test_budget_measurements_and_enforce_failure_preserve_precedence(self) -> None:
        run = SyntheticFoundation(
            mode="enforce",
            elapsed_seconds=61,
            reservation={
                "reserved": False,
                "total": 4,
                "operation_count": 5,
                "violations": [
                    "max_prompt_evidence_bytes",
                    "max_prompt_evidence_rows",
                    "max_run_seconds",
                    "max_model_calls",
                ],
            },
        )
        input_value = {
            "rows": list(range(11)),
            "context": "x" * 1_100,
        }
        with self.assertRaisesRegex(
            FOUNDATION.HarnessPolicyError,
            "max_model_calls, max_prompt_evidence_bytes, max_prompt_evidence_rows, max_run_seconds",
        ):
            run.preflight_model_call(
                call_id="over-budget",
                input_value=input_value,
                requested_route=run.envelope.assigned_route,
                purpose="over budget",
            )
        self.assertEqual(
            [call[0] for call in run.store.calls],
            ["append_event", "reserve_budget_operation", "append_event"],
        )
        reservation = run.store.calls[1][2]
        self.assertEqual(
            reservation["preexisting_violations"],
            [
                "max_prompt_evidence_bytes",
                "max_prompt_evidence_rows",
                "max_run_seconds",
            ],
        )
        budget_payload = run.store.calls[2][4]
        self.assertEqual(
            budget_payload["violations"],
            [
                "max_model_calls",
                "max_prompt_evidence_bytes",
                "max_prompt_evidence_rows",
                "max_run_seconds",
            ],
        )
        self.assertFalse(budget_payload["observed"]["reserved"])
        self.assertEqual(run._model_calls, 0)


if __name__ == "__main__":
    unittest.main()
