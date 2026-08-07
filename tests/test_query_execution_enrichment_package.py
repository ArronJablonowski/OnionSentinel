"""Direct state-transition contracts for enrichment query execution."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query.execution import enrichment  # noqa: E402


class QueryExecutionError(ValueError):
    pass


def evidence(**overrides):
    value = {
        "schema": enrichment.SCHEMA,
        "status": "ok",
        "indicator_type": "domain",
        "indicator": "example.test",
        "cache_checked_first": True,
        "n8n_invoked": False,
        "query_digest": "a" * 64,
        "result_digest": "b" * 64,
        "evidence_ref": "enrichment:trusted",
    }
    value.update(overrides)
    return value


def request(query_id="enrich-1"):
    return {
        "query_id": query_id,
        "backend": "enrichment",
        "purpose": "Enrich a trusted domain.",
        "parameters": {"indicator_type": "domain", "indicator": "example.test"},
    }


def dependencies(executor):
    return enrichment.Dependencies(
        executor=executor,
        error_type=QueryExecutionError,
        handled_errors=(QueryExecutionError, OSError, urllib.error.URLError),
    )


class EnrichmentExecutionPackageTests(unittest.TestCase):
    def test_success_binds_evidence_and_audit_digests(self) -> None:
        expected = evidence()
        outcome = enrichment.execute(
            [request()], {"enabled": True},
            dependencies=dependencies(lambda _request, _config: expected),
        )
        self.assertEqual(len(outcome.results), 1)
        result = outcome.results[0]
        self.assertTrue(result["read_only"])
        self.assertIs(result["evidence"], expected)
        binding = result["trusted_query_audit"][0]
        self.assertEqual(binding["query_digest"], "a" * 64)
        self.assertEqual(binding["result_digest"], "b" * 64)
        self.assertEqual(binding["evidence_ref"], "enrichment:trusted")
        self.assertEqual(outcome.audits[0]["backend"], "enrichment")

    def test_disabled_backend_becomes_explicit_terminal_error(self) -> None:
        outcome = enrichment.execute(
            [request()], None,
            dependencies=dependencies(lambda *_args: evidence()),
        )
        self.assertEqual(outcome.audits, [])
        self.assertEqual(outcome.results[0]["status"], "error")
        self.assertIn("not enabled", outcome.results[0]["error"])

    def test_invalid_evidence_is_rejected_without_audit(self) -> None:
        for invalid in (None, {}, evidence(schema="wrong"), evidence(status="error")):
            with self.subTest(invalid=invalid):
                outcome = enrichment.execute(
                    [request()], {"enabled": True},
                    dependencies=dependencies(lambda *_args, value=invalid: value),
                )
                self.assertEqual(outcome.audits, [])
                self.assertEqual(outcome.results[0]["status"], "error")
                self.assertIn("invalid evidence", outcome.results[0]["error"])

    def test_transport_failure_is_bounded_and_does_not_drop_later_requests(self) -> None:
        def executor(value, _config):
            if value["query_id"] == "failed":
                raise urllib.error.URLError("relay unavailable")
            return evidence(indicator=value["query_id"])

        outcome = enrichment.execute(
            [request("failed"), request("succeeded")], {"enabled": True},
            dependencies=dependencies(executor),
        )
        self.assertEqual([item["status"] for item in outcome.results], ["error", "ok"])
        self.assertEqual(len(outcome.audits), 1)


if __name__ == "__main__":
    unittest.main()
