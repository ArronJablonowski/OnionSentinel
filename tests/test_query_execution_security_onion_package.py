"""Direct state-transition contracts for Security Onion broker execution."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query.execution import security_onion  # noqa: E402


class BrokerContractError(ValueError):
    pass


class QueryExecutionError(ValueError):
    pass


POLICY = security_onion.Policy(
    query_contract="investigation-v2", require_anchor_time=True
)


def context() -> dict:
    return {
        "context_id": "context-1",
        "case_id": "case-1",
        "actor_role": "incident_responder",
        "anchor": {"index": "alerts", "id": "alert-1"},
        "anchor_time": "2026-07-24T01:00:00Z",
        "time_envelope": {
            "start": "2026-07-24T00:00:00Z",
            "end": "2026-07-24T02:00:00Z",
        },
        "permitted_observables": {"ips": ["192.0.2.1"]},
    }


def request(index: int, *, observables=None) -> dict:
    return {
        "query_id": f"security-{index}",
        "backend": "elastic",
        "purpose": "Establish the timeline.",
        "parameters": {
            "pack": "network_flow",
            "window": {
                "start": "2026-07-24T00:00:00Z",
                "end": "2026-07-24T02:00:00Z",
            },
            "observables": observables or {
                "ips": [f"192.0.2.{index}"],
                "domains": [], "hosts": [], "users": [],
            },
            "size": 25,
            "aggregation": "events",
        },
    }


def artifact(*, complete=True, partial=False) -> dict:
    return {
        "model_evidence": {"controls_valid": True, "results": []},
        "complete": complete,
        "partial": partial,
        "query_audit": [{"query_id": "security-1", "status": "ok"}],
        "audit": {
            "security_onion_response_digest": "a" * 64,
            "authorization_context_digest": "b" * 64,
        },
    }


class Recorder:
    def __init__(self, *, deny="", projection_error="", returned=None):
        self.deny = deny
        self.projection_error = projection_error
        self.returned = artifact() if returned is None else returned
        self.proposals: list[dict] = []

    def project(self, value):
        if self.projection_error:
            raise BrokerContractError(self.projection_error)
        return dict(value)

    def authorize(self, proposal, _context):
        if proposal["queries"][0]["query_id"] == self.deny:
            raise BrokerContractError("observable not authorized")

    def executor(self, proposal, _context):
        self.proposals.append(proposal)
        return self.returned

    def dependencies(self):
        return security_onion.Dependencies(
            project_context=self.project,
            authorize=self.authorize,
            executor=self.executor,
            text=lambda value, limit: str(value or "").strip()[:limit],
            random_hex=lambda size: "ab" * size,
            bounded_audit=lambda rows: list(rows),
            safe_audit_summary=lambda value: {
                "complete": bool(value.get("complete")),
                "sha256": "c" * 64,
            },
            contract_error=BrokerContractError,
            query_error=QueryExecutionError,
        )


class SecurityOnionExecutionPackageTests(unittest.TestCase):
    def execute(self, requests, recorder=None, local_context=None):
        recorder = recorder or Recorder()
        outcome = security_onion.execute(
            requests, context() if local_context is None else local_context,
            round_number=2, policy=POLICY, dependencies=recorder.dependencies(),
        )
        return outcome, recorder

    def test_success_builds_governed_proposal_and_binds_response_audit(self) -> None:
        outcome, recorder = self.execute([request(1)])
        proposal = recorder.proposals[0]
        self.assertEqual(proposal["query_contract"], "investigation-v2")
        self.assertEqual(proposal["batch_id"], "case-1-r2-" + "ab" * 8)
        self.assertEqual(proposal["queries"][0]["dialect"], "elastic")
        result = outcome.results[0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["security_onion_response_digest"], "a" * 64)
        self.assertEqual(result["trusted_query_audit"][0]["query_id"], "security-1")
        self.assertEqual(outcome.audits[0]["backend"], "security_onion")

    def test_isolated_preflight_rejects_only_denied_request(self) -> None:
        outcome, recorder = self.execute(
            [request(1), request(2)], Recorder(deny="security-1")
        )
        self.assertEqual(outcome.results[0]["query_id"], "security-1")
        self.assertEqual(outcome.results[0]["status"], "rejected")
        self.assertEqual(recorder.proposals[0]["queries"][0]["query_id"], "security-2")

    def test_context_projection_failure_rejects_every_request_without_dispatch(self) -> None:
        outcome, recorder = self.execute(
            [request(1), request(2)], Recorder(projection_error="hidden field")
        )
        self.assertEqual([item["status"] for item in outcome.results], ["rejected"] * 2)
        self.assertEqual(recorder.proposals, [])
        self.assertTrue(all("isolated local authorization" in item["error"] for item in outcome.results))

    def test_query_and_distinct_observable_budgets_are_enforced_before_dispatch(self) -> None:
        outcome, recorder = self.execute([request(index) for index in range(1, 6)])
        self.assertEqual(outcome.results[0]["query_id"], "security-5")
        self.assertEqual(outcome.results[0]["status"], "rejected")
        self.assertEqual(len(recorder.proposals[0]["queries"]), 4)

        many = {"ips": [f"192.0.2.{index}" for index in range(24)]}
        extra = {"ips": ["198.51.100.2"]}
        outcome, recorder = self.execute([
            request(1, observables=many), request(2, observables=extra)
        ])
        self.assertEqual(outcome.results[0]["query_id"], "security-2")
        self.assertIn("24 distinct", outcome.results[0]["error"])
        self.assertEqual(len(recorder.proposals[0]["queries"]), 1)

    def test_malformed_broker_artifact_becomes_error_for_each_admitted_request(self) -> None:
        outcome, _recorder = self.execute(
            [request(1), request(2)], Recorder(returned={"complete": True})
        )
        self.assertEqual([item["status"] for item in outcome.results], ["error", "error"])
        self.assertTrue(all("no model evidence" in item["error"] for item in outcome.results))

    def test_partial_broker_artifact_remains_explicitly_partial(self) -> None:
        outcome, _recorder = self.execute(
            [request(1)], Recorder(returned=artifact(complete=False, partial=True))
        )
        self.assertEqual(outcome.results[0]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
