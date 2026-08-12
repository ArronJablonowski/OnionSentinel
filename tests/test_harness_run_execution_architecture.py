from __future__ import annotations

import importlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

EXECUTION = importlib.import_module("harness_run_execution")


class FakeResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, authorization, executed_queries=0):
        self.authorization = authorization
        self.executed_queries = executed_queries

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, sql, parameters):
        if "FROM harness_events" in sql:
            row = (
                {"payload_json": json.dumps(self.authorization)}
                if self.authorization is not None
                else None
            )
            return FakeResult(row)
        if "FROM harness_tool_calls" in sql:
            return FakeResult({"executed_queries": self.executed_queries})
        raise AssertionError(sql)


class FakeStore:
    def __init__(self, reservation=None):
        self.path = Path("/synthetic/harness.sqlite3")
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

    def record_model_call(self, run_id, **kwargs):
        self.calls.append(("record_model_call", run_id, kwargs))

    def register_evidence(self, run_id, **kwargs):
        self.calls.append(("register_evidence", run_id, kwargs))

    def record_tool_call(self, run_id, **kwargs):
        self.calls.append(("record_tool_call", run_id, kwargs))


class SyntheticRun(EXECUTION.HarnessRunExecution):
    def __init__(self, *, mode="shadow", reservation=None):
        self.run_id = "run-1"
        self.store = FakeStore(reservation)
        self.policy = SimpleNamespace(
            mode=mode,
            budgets={
                "max_model_calls": 4,
                "max_queries_per_round": 4,
                "max_query_rounds": 3,
                "max_queries_total": 10,
            },
        )
        self._model_calls = 0
        self._queries_total = 0
        self._query_rounds = 0
        self._phase_counts = {}

    def _enforce_budget(self, **kwargs):
        self.store.calls.append(("enforce_budget", kwargs))
        if kwargs["violations"] and self.policy.mode == "enforce":
            raise EXECUTION.HarnessPolicyError(
                f'{kwargs["operation"]} exceeds harness budget: '
                + ", ".join(sorted(set(kwargs["violations"])))
            )


class HarnessRunExecutionArchitectureTests(unittest.TestCase):
    def test_stable_mixin_surface_and_signatures(self) -> None:
        self.assertEqual(
            str(inspect.signature(EXECUTION.HarnessRunExecution.phase)),
            "(self, phase: 'str', route: 'str' = '', reason: 'str' = '') -> 'None'",
        )
        self.assertEqual(
            str(inspect.signature(EXECUTION.HarnessRunExecution.model_call)),
            "(self, *, call_id: 'str', purpose: 'str', requested_route: 'str', response: 'Mapping[str, Any]', input_value: 'Any', duration_seconds: 'float', independent_review: 'bool' = False, status: 'str' = 'completed') -> 'None'",
        )
        self.assertEqual(
            str(inspect.signature(EXECUTION.HarnessRunExecution.query_round)),
            "(self, round_result: 'Mapping[str, Any]') -> 'None'",
        )
        self.assertFalse(
            {"PHASE_STAGE_MAP", "HarnessRunExecution"}.difference(vars(EXECUTION))
        )

    def test_model_call_preserves_observation_reservation_and_ledger_order(self) -> None:
        route = "codex-cli:gpt-5.6-sol:high"
        authorization = {
            "allowed": True,
            "requested_route": route,
            "independent_review": False,
        }
        run = SyntheticRun()
        response = {"_analysis_model_route": route, "answer": "bounded"}
        with mock.patch.object(
            EXECUTION,
            "_connect",
            return_value=FakeConnection(authorization),
        ):
            run.model_call(
                call_id="primary-1",
                purpose="primary analysis",
                requested_route=route,
                response=response,
                input_value={"prompt": "not persisted"},
                duration_seconds=1.234,
            )
        self.assertEqual(
            [call[0] for call in run.store.calls],
            ["append_event", "reserve_budget_operation", "record_model_call"],
        )
        observation = run.store.calls[0]
        self.assertEqual(observation[2:4], ("policy.model-observation", "primary-analysis"))
        self.assertEqual(
            observation[4],
            {
                "call_id": "primary-1",
                "requested_route": route,
                "observed_route": route,
                "independent_review": False,
                "response_present": True,
                "allowed": True,
                "reason": "authorized route and collector-observed route agree",
                "policy_mode": "shadow",
            },
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
            },
        )
        recorded = run.store.calls[2][2]
        self.assertEqual(recorded["duration_ms"], 1234)
        self.assertEqual(recorded["input_digest"], EXECUTION.digest_json({"prompt": "not persisted"}))
        self.assertIs(recorded["response"], response)
        self.assertEqual(run._model_calls, 1)

    def test_model_observation_refusal_precedes_budget_and_recording(self) -> None:
        run = SyntheticRun(mode="enforce")
        authorization = {
            "allowed": True,
            "requested_route": "codex-cli:gpt-5.6-sol:high",
            "independent_review": False,
        }
        with (
            mock.patch.object(
                EXECUTION,
                "_connect",
                return_value=FakeConnection(authorization),
            ),
            self.assertRaisesRegex(
                EXECUTION.HarnessPolicyError,
                "collector-observed route differs",
            ),
        ):
            run.model_call(
                call_id="mismatch",
                purpose="primary",
                requested_route="codex-cli:gpt-5.6-sol:high",
                response={"_analysis_model_route": "ollama:other"},
                input_value={},
                duration_seconds=0.1,
            )
        self.assertEqual([call[0] for call in run.store.calls], ["append_event"])
        self.assertFalse(run.store.calls[0][4]["allowed"])

    def test_query_round_preserves_evidence_tool_and_summary_order(self) -> None:
        query_digest = "a" * 64
        result_digest = "b" * 64
        run = SyntheticRun(
            reservation={
                "reserved": True,
                "total": 2,
                "operation_count": 1,
                "violations": [],
            }
        )
        round_result = {
            "round": 1,
            "requests": [
                {
                    "query_id": "q-1",
                    "backend": "elastic",
                    "purpose": "prove exact result",
                }
            ],
            "results": [
                {
                    "query_id": "q-1",
                    "backend": "elastic",
                    "status": "ok",
                    "read_only": True,
                    "evidence": {"returned_rows": 1},
                    "trusted_query_audit": [
                        {
                            "query_id": "q-1",
                            "query_digest": query_digest,
                            "result_digest": result_digest,
                            "status": "ok",
                            "returned_rows": 1,
                            "truncated": False,
                        }
                    ],
                },
                {
                    "query_id": "q-rejected",
                    "backend": "osquery",
                    "purpose": "rejected proposal",
                    "status": "denied",
                    "read_only": True,
                },
            ],
        }
        with mock.patch.object(
            EXECUTION,
            "_connect",
            return_value=FakeConnection(None, executed_queries=1),
        ):
            run.query_round(round_result)
        self.assertEqual(
            [call[0] for call in run.store.calls],
            [
                "reserve_budget_operation",
                "register_evidence",
                "record_tool_call",
                "record_tool_call",
                "append_event",
            ],
        )
        evidence = run.store.calls[1][2]
        self.assertEqual(evidence["evidence_ref"], f"query:{query_digest}:{result_digest}")
        self.assertEqual(evidence["source_class"], "security_onion_investigation_query")
        self.assertTrue(evidence["corroborating"])
        tools = [call[2] for call in run.store.calls if call[0] == "record_tool_call"]
        self.assertEqual([tool["call_id"] for tool in tools], ["round-1-q-1", "round-1-q-rejected"])
        self.assertEqual([tool["status"] for tool in tools], ["ok", "denied"])
        summary = run.store.calls[-1]
        self.assertEqual(summary[2:4], ("queries.completed", "query-execution"))
        self.assertEqual(
            summary[4],
            {
                "round": 1,
                "request_count": 1,
                "result_count": 2,
                "rejected_proposal_count": 1,
                "status_counts": {"ok": 1, "denied": 1},
                "backend_counts": {"elastic": 1, "osquery": 1},
                "trusted_query_digests": [query_digest],
                "budget_violations": [],
            },
        )
        self.assertEqual(run._query_rounds, 1)
        self.assertEqual(run._queries_total, 2)

    def test_query_budget_refusal_precedes_evidence_and_tool_ledgers(self) -> None:
        run = SyntheticRun(
            mode="enforce",
            reservation={
                "reserved": False,
                "total": 11,
                "operation_count": 4,
                "violations": ["max_queries_total"],
            },
        )
        with self.assertRaisesRegex(
            EXECUTION.HarnessPolicyError,
            "query batch exceeds harness budget: max_queries_total",
        ):
            run.query_round(
                {
                    "round": 1,
                    "requests": [{"query_id": "q-1", "backend": "elastic"}],
                    "results": [],
                }
            )
        self.assertEqual(
            [call[0] for call in run.store.calls],
            ["reserve_budget_operation", "enforce_budget"],
        )


if __name__ == "__main__":
    unittest.main()
