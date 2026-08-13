from __future__ import annotations

import ast
import importlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

OWNER = importlib.import_module("harness_store_trace_repository")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_trace_repository.py").read_text(encoding="utf-8")
    )
    owner = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "HarnessStoreTraceRepository"
    )
    target = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class Cursor:
    def __init__(self, trace, response):
        self.trace = trace
        self.response = response

    def fetchone(self):
        self.trace.append(("fetchone",))
        return self.response

    def fetchall(self):
        self.trace.append(("fetchall",))
        return self.response


class Connection:
    def __init__(self, trace, responses):
        self.trace = trace
        self.responses = list(responses)

    def __enter__(self):
        self.trace.append(("enter",))
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.trace.append(
            (
                "exit",
                exception_type.__name__ if exception_type is not None else None,
            )
        )
        return False

    def execute(self, query, parameters=None):
        normalized = " ".join(query.split())
        self.trace.append(("execute", normalized, parameters))
        response = self.responses.pop(0) if self.responses else None
        return Cursor(self.trace, response)

    def commit(self):
        self.trace.append(("commit",))


class HarnessStoreTraceRepositoryProjectionTests(unittest.TestCase):
    def repository(self):
        repository = OWNER.HarnessStoreTraceRepository()
        repository.path = Path("/synthetic/harness.sqlite3")
        return repository

    def test_public_signatures_and_current_debt_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(OWNER.HarnessStoreTraceRepository.finish)),
            "(self, run_id: 'str', *, status: 'str', reason: 'str' = '', "
            "summary: 'Mapping[str, Any] | None' = None) -> 'None'",
        )
        self.assertEqual(
            str(inspect.signature(OWNER.HarnessStoreTraceRepository.export_trace)),
            "(self, run_id: 'str') -> 'dict[str, Any]'",
        )
        self.assertEqual(function_metrics("finish"), (87, 14))
        self.assertEqual(function_metrics("export_trace"), (98, 9))

    def invoke_finish(
        self,
        *,
        status="succeeded",
        current_status="running",
        reason="terminal reason",
        summary=None,
    ):
        trace = []
        summary = {"answer": 42} if summary is None else summary
        connection = Connection(trace, [None, {"status": current_status}, None])
        repository = self.repository()
        event = {"created_at": "event-time", "event_id": "event-1"}

        def connect(path):
            trace.append(("connect", path))
            return connection

        def digest(value):
            trace.append(("digest", value))
            return "reason-digest"

        def manifest(value, run_id):
            trace.append(("manifest", value, run_id))
            return {"ledger": "digest"}

        def append(value, **kwargs):
            trace.append(("append", value, kwargs))
            return event

        def bounded(value):
            trace.append(("bounded", value))
            return {"bounded": value}

        def canonical(value):
            trace.append(("canonical", value))
            return "summary-json"

        def audit(value):
            trace.append(("audit", value))

        repository._append_event_tx = append
        repository._audit_event = audit
        with (
            mock.patch.object(OWNER, "_connect", side_effect=connect),
            mock.patch.object(OWNER, "digest_json", side_effect=digest),
            mock.patch.object(OWNER, "ledger_manifest", side_effect=manifest),
            mock.patch.object(OWNER, "bounded_metadata", side_effect=bounded),
            mock.patch.object(OWNER, "canonical_json", side_effect=canonical),
        ):
            result = repository.finish(
                "run-1",
                status=status,
                reason=reason,
                summary=summary,
            )
        return result, trace, connection, summary, event

    def test_finish_preserves_transaction_event_update_and_audit_order(self) -> None:
        result, trace, connection, summary, event = self.invoke_finish()

        self.assertIsNone(result)
        self.assertEqual(connection.responses, [])
        self.assertEqual(
            [item[0] for item in trace],
            [
                "connect",
                "enter",
                "execute",
                "execute",
                "fetchone",
                "digest",
                "manifest",
                "append",
                "bounded",
                "canonical",
                "execute",
                "commit",
                "exit",
                "audit",
            ],
        )
        self.assertEqual(
            trace[2],
            ("execute", "BEGIN IMMEDIATE", None),
        )
        self.assertEqual(
            trace[3],
            (
                "execute",
                "SELECT status FROM harness_runs WHERE run_id = ?",
                ("run-1",),
            ),
        )
        self.assertEqual(trace[5], ("digest", "terminal reason"))
        self.assertEqual(trace[6], ("manifest", connection, "run-1"))
        append = trace[7]
        self.assertIs(append[1], connection)
        self.assertEqual(
            append[2],
            {
                "run_id": "run-1",
                "event_type": "run.succeeded",
                "stage": OWNER.Stage.COMPLETE.value,
                "payload": {
                    "reason_present": True,
                    "reason_digest": "reason-digest",
                    "summary": summary,
                    "ledger_manifest": {"ledger": "digest"},
                },
                "idempotency_key": "run.terminal:succeeded",
            },
        )
        self.assertEqual(
            trace[10],
            (
                "execute",
                "UPDATE harness_runs SET status = ?, stage = ?, completed_at = ?, "
                "updated_at = ?, terminal_reason = ?, summary_json = ?, revision = "
                "revision + 1 WHERE run_id = ?",
                (
                    "succeeded",
                    OWNER.Stage.COMPLETE.value,
                    "event-time",
                    "event-time",
                    "sha256:reason-digest",
                    "summary-json",
                    "run-1",
                ),
            ),
        )
        self.assertEqual(trace[8], ("bounded", summary))
        self.assertEqual(trace[9], ("canonical", {"bounded": summary}))
        self.assertEqual(trace[-2:], [("exit", None), ("audit", event)])

    def test_finish_status_stage_manifest_and_empty_reason_policy(self) -> None:
        cases = [
            ("succeeded", OWNER.Stage.COMPLETE.value, True),
            ("failed", OWNER.Stage.FAILED.value, True),
            ("cancelled", OWNER.Stage.FAILED.value, True),
            ("waiting-for-review", OWNER.Stage.HUMAN_REVIEW.value, False),
        ]
        for status, stage, manifest_expected in cases:
            with self.subTest(status=status):
                _, trace, _, _, _ = self.invoke_finish(
                    status=status,
                    current_status=status,
                    reason="",
                    summary={},
                )
                names = [item[0] for item in trace]
                self.assertEqual("manifest" in names, manifest_expected)
                append = next(item for item in trace if item[0] == "append")
                self.assertEqual(append[2]["stage"], stage)
                self.assertEqual(append[2]["payload"]["reason_present"], False)
                self.assertEqual(append[2]["payload"]["summary"], {})
                self.assertEqual(
                    "ledger_manifest" in append[2]["payload"],
                    manifest_expected,
                )
                update = [item for item in trace if item[0] == "execute"][-1]
                self.assertEqual(update[2][4], "")

    def test_finish_rejects_invalid_status_and_run_state_before_hashing(self) -> None:
        repository = self.repository()
        with mock.patch.object(OWNER, "_connect") as connect:
            with self.assertRaisesRegex(OWNER.HarnessPolicyError, "invalid terminal"):
                repository.finish("run-1", status="running")
            connect.assert_not_called()

        for current, message in [
            (None, "unknown harness run"),
            ({"status": "succeeded"}, "different terminal status"),
        ]:
            with self.subTest(current=current):
                trace = []
                connection = Connection(trace, [None, current])
                with (
                    mock.patch.object(OWNER, "_connect", return_value=connection),
                    mock.patch.object(OWNER, "digest_json") as digest,
                    self.assertRaisesRegex(OWNER.HarnessIntegrityError, message),
                ):
                    repository.finish("run-1", status="failed")
                digest.assert_not_called()
                self.assertEqual(trace[-1][0], "exit")
                self.assertEqual(trace[-1][1], "HarnessIntegrityError")
                self.assertNotIn("commit", [item[0] for item in trace])

    def export_connection(self, trace, *, event_payload='{"event":1}'):
        return Connection(
            trace,
            [
                {"run_id": "run-1", "status": "running"},
                [
                    {
                        "event_id": "event-1",
                        "sequence": 1,
                        "payload_json": event_payload,
                    }
                ],
                [
                    {
                        "evidence_ref": "evidence-1",
                        "metadata_json": '{"source":"sensor"}',
                    }
                ],
                [{"hypothesis_id": "hypothesis-1"}],
                [{"decision_id": "decision-1"}],
                [{"call_id": "model-1"}],
                [{"call_id": "tool-1"}],
                [{"reservation_id": "reservation-1"}],
            ],
        )

    def test_export_preserves_queries_projection_close_timestamp_and_verify_order(
        self,
    ) -> None:
        trace = []
        connection = self.export_connection(trace)
        repository = self.repository()

        def connect(path):
            trace.append(("connect", path))
            return connection

        def now():
            trace.append(("utc_now",))
            return "export-time"

        def verify(run_id):
            trace.append(("verify", run_id))
            return {"ok": True}

        repository.verify_chain = verify
        with (
            mock.patch.object(OWNER, "_connect", side_effect=connect),
            mock.patch.object(OWNER, "utc_now", side_effect=now),
        ):
            result = repository.export_trace("run-1")

        self.assertEqual(
            list(result),
            [
                "schema",
                "exported_at",
                "run",
                "events",
                "evidence",
                "hypotheses",
                "decisions",
                "model_calls",
                "tool_calls",
                "budget_reservations",
                "integrity",
            ],
        )
        self.assertEqual(result["schema"], OWNER.TRACE_SCHEMA)
        self.assertEqual(result["exported_at"], "export-time")
        self.assertEqual(result["run"], {"run_id": "run-1", "status": "running"})
        self.assertEqual(
            result["events"],
            [
                {
                    "event_id": "event-1",
                    "sequence": 1,
                    "payload_json": '{"event":1}',
                    "payload": {"event": 1},
                }
            ],
        )
        self.assertEqual(
            result["evidence"],
            [
                {
                    "evidence_ref": "evidence-1",
                    "metadata_json": '{"source":"sensor"}',
                    "metadata": {"source": "sensor"},
                }
            ],
        )
        self.assertEqual(result["hypotheses"], [{"hypothesis_id": "hypothesis-1"}])
        self.assertEqual(result["decisions"], [{"decision_id": "decision-1"}])
        self.assertEqual(result["model_calls"], [{"call_id": "model-1"}])
        self.assertEqual(result["tool_calls"], [{"call_id": "tool-1"}])
        self.assertEqual(
            result["budget_reservations"],
            [{"reservation_id": "reservation-1"}],
        )
        self.assertEqual(result["integrity"], {"ok": True})

        queries = [item[1] for item in trace if item[0] == "execute"]
        self.assertEqual(
            queries,
            [
                "SELECT * FROM harness_runs WHERE run_id = ?",
                "SELECT * FROM harness_events WHERE run_id = ? ORDER BY sequence",
                "SELECT * FROM harness_evidence WHERE run_id = ? ORDER BY evidence_ref",
                "SELECT * FROM harness_hypotheses WHERE run_id = ? ORDER BY hypothesis_id",
                "SELECT * FROM harness_decisions WHERE run_id = ? ORDER BY created_at, decision_id",
                "SELECT * FROM harness_model_calls WHERE run_id = ? ORDER BY created_at, call_id",
                "SELECT * FROM harness_tool_calls WHERE run_id = ? ORDER BY round_number, call_id",
                "SELECT * FROM harness_budget_reservations WHERE run_id = ? ORDER BY reservation_type, reservation_id",
            ],
        )
        for item in (item for item in trace if item[0] == "execute"):
            self.assertEqual(item[2], ("run-1",))
        self.assertLess(trace.index(("exit", None)), trace.index(("utc_now",)))
        self.assertLess(trace.index(("utc_now",)), trace.index(("verify", "run-1")))

    def test_export_unknown_run_and_invalid_json_fail_before_later_work(self) -> None:
        repository = self.repository()
        trace = []
        connection = Connection(trace, [None])
        with (
            mock.patch.object(OWNER, "_connect", return_value=connection),
            mock.patch.object(OWNER, "utc_now") as now,
            mock.patch.object(repository, "verify_chain") as verify,
            self.assertRaisesRegex(OWNER.HarnessIntegrityError, "unknown harness run"),
        ):
            repository.export_trace("missing")
        now.assert_not_called()
        verify.assert_not_called()
        self.assertEqual(len([item for item in trace if item[0] == "execute"]), 1)
        self.assertEqual(trace[-1], ("exit", "HarnessIntegrityError"))

        trace = []
        connection = self.export_connection(trace, event_payload="not-json")
        with (
            mock.patch.object(OWNER, "_connect", return_value=connection),
            mock.patch.object(OWNER, "utc_now") as now,
            mock.patch.object(repository, "verify_chain") as verify,
            self.assertRaises(json.JSONDecodeError),
        ):
            repository.export_trace("run-1")
        now.assert_not_called()
        verify.assert_not_called()
        self.assertEqual(len([item for item in trace if item[0] == "execute"]), 2)
        self.assertEqual(trace[-1], ("exit", "JSONDecodeError"))


if __name__ == "__main__":
    unittest.main()
