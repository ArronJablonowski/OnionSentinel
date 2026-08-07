"""Direct state-transition contracts for live OSQuery execution."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query.execution import endpoint  # noqa: E402


class EndpointExecutionError(ValueError):
    pass


def normalize_query(value: str) -> str:
    return " ".join(value.split())


def request(query_id="endpoint-1", target="workstation-1", query="SELECT * FROM processes;"):
    return {
        "query_id": query_id,
        "backend": "osquery",
        "purpose": "Confirm the process inventory.",
        "parameters": {"target_alias": target, "query": query},
    }


def result(value: dict) -> dict:
    query = normalize_query(value["parameters"]["query"])
    return {
        "target_alias": value["parameters"]["target_alias"],
        "query": query,
        "query_digest": hashlib.sha256(query.encode()).hexdigest(),
        "purpose": value["purpose"],
        "status": "ok",
        "rows": [{"pid": "1"}],
        "total_rows": 1,
        "truncated": False,
        "duration_ms": 12,
        "error": "",
    }


class Recorder:
    def __init__(self, requests: list[dict], *, target_bound=True, mutate=None):
        self.requests = requests
        self.target_is_bound = target_bound
        self.mutate = mutate
        self.evidence_batches: list[dict] = []
        self.failures: list[dict] = []
        self.executor_calls = 0

    def executor(self, *, case_id, requests, config, persist):
        self.executor_calls += 1
        evidence = {
            "case_id": case_id,
            "results": [result(item) for item in self.requests],
            "read_only": True,
        }
        if self.mutate:
            self.mutate(evidence)
        return evidence

    def dependencies(self) -> endpoint.Dependencies:
        return endpoint.Dependencies(
            executor=self.executor,
            validate_artifact=lambda value, **_kwargs: value,
            case_id=lambda _package: "case-1",
            target_bound=lambda _package, _alias, _config: self.target_is_bound,
            support_bindings=lambda *_args: [{"observable": "trusted"}],
            accumulate_evidence=lambda _package, value: self.evidence_batches.append(value),
            accumulate_failure=lambda _package, **value: self.failures.append(value),
            normalize_query=normalize_query,
            text=lambda value, limit: str(value or "").strip()[:limit],
            bounded_audit=lambda rows: rows,
            safe_audit_summary=lambda _value: {"complete": True},
            client_error=EndpointExecutionError,
            handled_errors=(EndpointExecutionError, OSError),
        )


class EndpointExecutionPackageTests(unittest.TestCase):
    def test_success_requires_exact_identity_and_accumulates_support_bindings(self) -> None:
        requests = [request()]
        recorder = Recorder(requests)
        outcome = endpoint.execute(
            requests, {}, {"enabled": True}, dependencies=recorder.dependencies()
        )
        self.assertEqual(outcome.results[0]["status"], "ok")
        self.assertTrue(outcome.results[0]["read_only"])
        binding = outcome.results[0]["trusted_query_audit"][0]
        self.assertEqual(binding["query_digest"], result(request())["query_digest"])
        self.assertEqual(binding["returned_rows"], 1)
        self.assertNotIn("support_bindings", outcome.results[0]["evidence"])
        self.assertEqual(
            recorder.evidence_batches[0]["results"][0]["support_bindings"],
            [{"observable": "trusted"}],
        )
        self.assertEqual(outcome.audits, [{"backend": "osquery", "complete": True}])

    def test_disabled_or_unbound_target_fails_before_dispatch(self) -> None:
        for config, bound in ((None, True), ({"enabled": True}, False)):
            requests = [request()]
            recorder = Recorder(requests, target_bound=bound)
            outcome = endpoint.execute(
                requests, {}, config, dependencies=recorder.dependencies()
            )
            self.assertEqual(recorder.executor_calls, 0)
            self.assertEqual(outcome.results[0]["status"], "error")
            self.assertFalse(recorder.failures[0]["dispatch_possible"])

    def test_coverage_mismatch_is_a_post_dispatch_failure(self) -> None:
        requests = [request()]
        recorder = Recorder(requests, mutate=lambda value: value.update(results=[]))
        outcome = endpoint.execute(
            requests, {}, {"enabled": True}, dependencies=recorder.dependencies()
        )
        self.assertEqual(outcome.results[0]["status"], "error")
        self.assertIn("coverage", outcome.results[0]["error"])
        self.assertTrue(recorder.failures[0]["dispatch_possible"])

    def test_duplicate_submission_identity_fails_closed(self) -> None:
        requests = [request("one"), request("two")]
        recorder = Recorder([requests[0]])
        outcome = endpoint.execute(
            requests, {}, {"enabled": True}, dependencies=recorder.dependencies()
        )
        self.assertEqual([item["status"] for item in outcome.results], ["error", "error"])
        self.assertIn("duplicate query identity", outcome.results[0]["error"])

    def test_empty_batch_does_not_compute_case_or_dispatch(self) -> None:
        recorder = Recorder([])
        self.assertEqual(
            endpoint.execute([], {}, None, dependencies=recorder.dependencies()),
            endpoint.Outcome(results=[], audits=[]),
        )
        self.assertEqual(recorder.executor_calls, 0)


if __name__ == "__main__":
    unittest.main()
