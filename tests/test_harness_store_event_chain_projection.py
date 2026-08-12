from __future__ import annotations

import ast
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

FOUNDATION = importlib.import_module("harness_store_foundation")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_foundation.py").read_text(encoding="utf-8")
    )
    class_name, function_name = name.split(".", 1)
    owner = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    target = next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
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


class TraceRow:
    def __init__(self, trace, name, values):
        self.trace = trace
        self.name = name
        self.values = dict(values)

    def keys(self):
        self.trace.append((f"{self.name}.keys",))
        return self.values.keys()

    def __getitem__(self, key):
        self.trace.append((f"{self.name}.get", key))
        return self.values[key]


class Cursor:
    def __init__(self, trace, row):
        self.trace = trace
        self.row = row

    def fetchone(self):
        self.trace.append(("fetchone",))
        return self.row


class Connection:
    def __init__(self, trace, rows):
        self.trace = trace
        self.rows = list(rows)

    def execute(self, query, parameters):
        normalized = " ".join(query.split())
        self.trace.append(("execute", normalized, parameters))
        row = self.rows.pop(0) if normalized.startswith("SELECT") else None
        return Cursor(self.trace, row)


class Hash:
    def __init__(self, trace, digest):
        self.trace = trace
        self.digest = digest

    def hexdigest(self):
        self.trace.append(("hexdigest",))
        return self.digest


class HarnessStoreEventChainProjectionTests(unittest.TestCase):
    def invoke(
        self,
        *,
        rows,
        created_at="provided-time",
        event_type="run.phase",
        stage="primary-analysis",
        payload=None,
        idempotency_key="event-key",
        trace=None,
    ):
        trace = [] if trace is None else trace
        connection = Connection(trace, rows)
        payload = {"secret": "redacted", "rows": [1, 2]} if payload is None else payload
        bounded = {"bounded": True, "rows": [1, 2]}
        canonical = '{"bounded":true,"rows":[1,2]}'
        payload_digest = "p" * 64
        event_digest = "d" * 64

        def bounded_metadata(value):
            trace.append(("bounded_metadata", value))
            return bounded

        def canonical_json(value):
            trace.append(("canonical_json", value))
            return canonical

        def sha256(value):
            trace.append(("sha256", value))
            return Hash(trace, payload_digest)

        def utc_now():
            trace.append(("utc_now",))
            return "generated-time"

        def digest_json(value):
            trace.append(("digest_json", value))
            return event_digest

        with (
            mock.patch.object(
                FOUNDATION,
                "bounded_metadata",
                side_effect=bounded_metadata,
            ),
            mock.patch.object(
                FOUNDATION,
                "canonical_json",
                side_effect=canonical_json,
            ),
            mock.patch.object(
                FOUNDATION.hashlib,
                "sha256",
                side_effect=sha256,
            ),
            mock.patch.object(FOUNDATION, "utc_now", side_effect=utc_now),
            mock.patch.object(
                FOUNDATION,
                "digest_json",
                side_effect=digest_json,
            ),
        ):
            result = FOUNDATION.HarnessStoreFoundation._append_event_tx(
                connection,
                run_id="run-1",
                event_type=event_type,
                stage=stage,
                payload=payload,
                idempotency_key=idempotency_key,
                created_at=created_at,
            )
        return result, trace

    def test_static_signature_and_current_debt_are_exact(self) -> None:
        self.assertEqual(
            str(
                inspect.signature(
                    FOUNDATION.HarnessStoreFoundation._append_event_tx
                )
            ),
            "(connection: 'sqlite3.Connection', *, run_id: 'str', event_type: 'str', stage: 'str', payload: 'Mapping[str, Any]', idempotency_key: 'str', created_at: 'str | None' = None) -> 'dict[str, Any]'",
        )
        self.assertEqual(
            function_metrics("HarnessStoreFoundation._append_event_tx"),
            (83, 8),
        )

    def test_new_event_preserves_payload_chain_insert_and_result_projection(self) -> None:
        trace = []
        previous = TraceRow(
            trace,
            "previous",
            {"sequence": "4", "event_sha256": "c" * 64},
        )

        result, trace = self.invoke(rows=[None, previous], trace=trace)

        self.assertEqual(
            [item[0] for item in trace[:6]],
            [
                "bounded_metadata",
                "canonical_json",
                "sha256",
                "hexdigest",
                "execute",
                "fetchone",
            ],
        )
        selects = [item for item in trace if item[0] == "execute"]
        self.assertEqual(
            selects[0],
            (
                "execute",
                "SELECT * FROM harness_events WHERE run_id = ? AND idempotency_key = ?",
                ("run-1", "event-key"),
            ),
        )
        self.assertEqual(
            selects[1],
            (
                "execute",
                "SELECT sequence, event_sha256 FROM harness_events WHERE run_id = ? ORDER BY sequence DESC LIMIT 1",
                ("run-1",),
            ),
        )
        body = {
            "run_id": "run-1",
            "sequence": 5,
            "idempotency_key": "event-key",
            "event_type": "run.phase",
            "stage": "primary-analysis",
            "created_at": "provided-time",
            "payload_sha256": "p" * 64,
            "previous_event_sha256": "c" * 64,
        }
        self.assertIn(("digest_json", body), trace)
        insert = selects[2]
        self.assertEqual(
            insert[1],
            "INSERT INTO harness_events( run_id, sequence, event_id, idempotency_key, event_type, stage, created_at, payload_json, payload_sha256, previous_event_sha256, event_sha256 ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        self.assertEqual(
            insert[2],
            (
                "run-1",
                5,
                f"evt-{'d' * 32}",
                "event-key",
                "run.phase",
                "primary-analysis",
                "provided-time",
                '{"bounded":true,"rows":[1,2]}',
                "p" * 64,
                "c" * 64,
                "d" * 64,
            ),
        )
        self.assertEqual(
            result,
            {
                **body,
                "event_id": f"evt-{'d' * 32}",
                "payload_json": '{"bounded":true,"rows":[1,2]}',
                "event_sha256": "d" * 64,
            },
        )
        self.assertNotIn("utc_now", [item[0] for item in trace])

    def test_empty_chain_and_false_created_at_use_zero_hash_and_clock(self) -> None:
        result, trace = self.invoke(rows=[None, None], created_at="")

        self.assertIn(("utc_now",), trace)
        body = next(item[1] for item in trace if item[0] == "digest_json")
        self.assertEqual(body["sequence"], 1)
        self.assertEqual(body["previous_event_sha256"], "0" * 64)
        self.assertEqual(body["created_at"], "generated-time")
        self.assertEqual(result["created_at"], "generated-time")

    def test_matching_replay_returns_existing_without_chain_or_time_work(self) -> None:
        external_trace = []
        existing_values = {
            "event_type": "run.phase",
            "stage": "primary-analysis",
            "payload_sha256": "p" * 64,
            "event_id": "evt-existing",
            "sequence": 3,
        }
        existing = TraceRow(external_trace, "existing", existing_values)

        result, trace = self.invoke(rows=[existing], trace=external_trace)

        self.assertEqual(result, existing_values)
        self.assertEqual(
            [
                item
                for item in external_trace
                if item[0] == "existing.get"
            ][:3],
            [
                ("existing.get", "event_type"),
                ("existing.get", "stage"),
                ("existing.get", "payload_sha256"),
            ],
        )
        self.assertEqual(
            len([item for item in external_trace if item[0] == "execute"]),
            1,
        )
        self.assertNotIn("digest_json", [item[0] for item in external_trace])
        self.assertNotIn("utc_now", [item[0] for item in external_trace])

    def test_replay_collision_checks_fields_in_short_circuit_order(self) -> None:
        scenarios = (
            (
                {
                    "event_type": "other",
                    "stage": "other",
                    "payload_sha256": "other",
                },
                ["event_type"],
            ),
            (
                {
                    "event_type": "run.phase",
                    "stage": "other",
                    "payload_sha256": "other",
                },
                ["event_type", "stage"],
            ),
            (
                {
                    "event_type": "run.phase",
                    "stage": "primary-analysis",
                    "payload_sha256": "other",
                },
                ["event_type", "stage", "payload_sha256"],
            ),
        )
        for values, expected_accesses in scenarios:
            with self.subTest(values=values):
                trace = []
                existing = TraceRow(trace, "existing", values)
                with self.assertRaisesRegex(
                    FOUNDATION.HarnessIntegrityError,
                    "^idempotency key was reused with different event content$",
                ):
                    self.invoke(rows=[existing], trace=trace)
                self.assertEqual(
                    [item[1] for item in trace if item[0] == "existing.get"],
                    expected_accesses,
                )


if __name__ == "__main__":
    unittest.main()
