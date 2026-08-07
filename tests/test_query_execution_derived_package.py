"""Direct state-transition contracts for PCAP/Zeek-derived execution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query.execution import derived  # noqa: E402


class DerivedExecutionError(ValueError):
    pass


def request(index: int) -> dict:
    return {
        "query_id": f"derived-{index}",
        "backend": "pcap_zeek",
        "purpose": "Confirm network evidence.",
        "parameters": {
            "operation": "zeek_connections",
            "filters": {"source_ip": f"192.0.2.{index}"},
            "indicator": "",
            "limit": 10,
        },
    }


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def result_for(query: dict) -> dict:
    return {
        "query": query,
        "audit": {
            "candidate_records_scanned": 20,
            "unique_records_matched": 2,
            "records_returned": 2,
            "result_truncated": False,
            "index_scan_truncated": False,
            "derived_views_considered": ["zeek.conn"],
        },
        "query_digest": digest(query),
        "result_digest": "b" * 64,
        "records": [{"source_ip": query["filters"]["source_ip"]}],
    }


def dependencies(*, fail: bool = False) -> derived.Dependencies:
    def executor(_context, submitted):
        if fail:
            raise DerivedExecutionError("source artifact unavailable")
        return {"results": [result_for(item) for item in submitted], "executed": {}}

    def validate(value, submitted):
        if len(value.get("results", [])) != len(submitted):
            raise DerivedExecutionError("coverage mismatch")
        return value

    return derived.Dependencies(
        executor=executor,
        validate_evidence=validate,
        source_digest=lambda context: digest(context),
        bounded_audit=lambda rows: rows,
        safe_audit_summary=lambda _value: {"complete": True},
        handled_errors=(DerivedExecutionError, OSError),
    )


class DerivedExecutionPackageTests(unittest.TestCase):
    def test_success_binds_source_query_result_and_reference(self) -> None:
        context = {"source": "trusted-pcap"}
        outcome = derived.execute(
            [request(1)], context, dependencies=dependencies()
        )
        self.assertEqual(outcome.results[0]["status"], "ok")
        binding = outcome.results[0]["trusted_query_audit"][0]
        self.assertEqual(binding["query_digest"], outcome.results[0]["evidence"]["query_digest"])
        self.assertEqual(binding["result_digest"], "b" * 64)
        self.assertTrue(binding["evidence_ref"].startswith(
            f"derived-pcap-zeek:{digest(context)[:16]}:"
        ))
        self.assertEqual(
            outcome.results[0]["evidence"]["evidence_ref"],
            binding["evidence_ref"],
        )
        self.assertEqual(outcome.audits, [{
            "backend": "derived-pcap-zeek", "complete": True
        }])

    def test_round_cap_rejects_overflow_without_executing_it(self) -> None:
        seen: list[list[dict]] = []
        deps = dependencies()
        wrapped = derived.Dependencies(
            **{
                **deps.__dict__,
                "executor": lambda context, submitted: (
                    seen.append(submitted)
                    or {"results": [result_for(item) for item in submitted], "executed": {}}
                ),
            }
        )
        outcome = derived.execute(
            [request(index) for index in range(1, 6)], {}, dependencies=wrapped
        )
        self.assertEqual(len(seen[0]), 4)
        self.assertEqual(len(outcome.results), 5)
        self.assertEqual(outcome.results[0]["query_id"], "derived-5")
        self.assertEqual(outcome.results[0]["status"], "rejected")
        self.assertEqual(
            [item["status"] for item in outcome.results[1:]], ["ok"] * 4
        )

    def test_batch_failure_projects_error_for_every_admitted_request(self) -> None:
        outcome = derived.execute(
            [request(1), request(2)], {}, dependencies=dependencies(fail=True)
        )
        self.assertEqual(outcome.audits, [])
        self.assertEqual([item["status"] for item in outcome.results], ["error", "error"])
        self.assertTrue(all(item["read_only"] for item in outcome.results))
        self.assertTrue(all("source artifact unavailable" in item["error"] for item in outcome.results))

    def test_empty_batch_is_a_noop_transition(self) -> None:
        self.assertEqual(
            derived.execute([], {}, dependencies=dependencies()),
            derived.Outcome(results=[], audits=[]),
        )


if __name__ == "__main__":
    unittest.main()
