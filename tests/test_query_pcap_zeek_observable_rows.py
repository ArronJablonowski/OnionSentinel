"""Characterize provenance-bound PCAP Zeek observable row projection."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import re
import unittest

from n8n.onion_sentinel.analysis.query import observables


class ExplodingRecordValue:
    def __str__(self) -> str:
        raise RuntimeError("record stringification failed")


class PcapZeekObservableRowCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = observables.ValidationPolicy(
            safe_domain_pattern=re.compile(r"[a-z0-9.-]+"),
            safe_atom_pattern=re.compile(r"[A-Za-z0-9_.:@/-]+"),
            maximum_queries_per_round=4,
            maximum_rows=3,
        )

    def dependencies(
        self, calls: list[object] | None = None
    ) -> observables.ValidationDependencies:
        trace = calls if calls is not None else []

        def text(value: object, limit: int) -> str:
            trace.append(("text", value, limit))
            return str(value or "")[:limit]

        def component(value: object, limit: int) -> str:
            trace.append(("component", value, limit))
            return f"component-{value}"[:limit]

        return observables.ValidationDependencies(text, component)

    def result(
        self,
        *,
        records: object,
        query_digest: object = "a" * 64,
        result_digest: object = "b" * 64,
        evidence_ref: object = "pcap-source",
        audit: object | None = None,
    ) -> dict[str, object]:
        audit_value = audit if audit is not None else {
            "query_id": "q-1",
            "status": "ok",
            "query_digest": query_digest,
            "result_digest": result_digest,
            "evidence_ref": evidence_ref,
        }
        return {
            "query_id": "q-1",
            "trusted_query_audit": [audit_value],
            "evidence": {
                "records": records,
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": evidence_ref,
            },
        }

    def project(
        self,
        value: dict[str, object],
        *,
        policy: observables.ValidationPolicy | None = None,
        calls: list[object] | None = None,
    ) -> list[tuple[object, str]]:
        return observables._pcap_zeek_rows(
            value,
            policy or self.policy,
            self.dependencies(calls),
        )

    def test_non_mapping_evidence_fails_before_dependency_calls(self) -> None:
        for evidence in (None, [], "evidence", 7):
            calls: list[object] = []
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    self.project({"evidence": evidence}, calls=calls), []
                )
                self.assertEqual(calls, [])

    def test_each_unbound_or_malformed_shape_fails_closed(self) -> None:
        valid = self.result(records=[])
        cases = (
            self.result(records={}),
            self.result(records=[], audit="invalid"),
            self.result(records=[], audit={
                "query_id": "q-1", "status": "ok",
                "query_digest": "c" * 64,
                "result_digest": "b" * 64, "evidence_ref": "pcap-source",
            }),
            self.result(records=[], audit={
                "query_id": "q-1", "status": "ok",
                "query_digest": "a" * 64,
                "result_digest": "c" * 64, "evidence_ref": "pcap-source",
            }),
            self.result(records=[], audit={
                "query_id": "q-1", "status": "ok",
                "query_digest": "a" * 64,
                "result_digest": "b" * 64, "evidence_ref": "other",
            }),
            self.result(records=[], query_digest="invalid"),
            self.result(records=[], result_digest="INVALID"),
        )
        self.assertEqual(self.project(valid), [])
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(self.project(value), [])

    def test_records_are_bounded_skip_malformed_and_retain_alias_and_index(self) -> None:
        first = {"source_ip": "192.0.2.1"}
        second = {"dns_query": "example.test"}
        records = ["ignored", first, second, {"source_ip": "192.0.2.4"}]

        rows = self.project(self.result(records=records))

        self.assertEqual(len(rows), 2)
        self.assertIs(rows[0][0], first)
        self.assertIs(rows[1][0], second)
        self.assertIn("record-1-", rows[0][1])
        self.assertIn("record-2-", rows[1][1])

        negative = self.project(
            self.result(records=[first, second, {}]),
            policy=replace(self.policy, maximum_rows=-1),
        )
        self.assertEqual([row[0] for row in negative], [first, second])

    def test_canonical_record_digest_and_dependency_order_are_exact(self) -> None:
        calls: list[object] = []
        record = {"z": 1, "a": [2, {"value": "x"}]}
        expected_digest = hashlib.sha256(json.dumps(
            record, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()

        rows = self.project(
            self.result(records=[record], evidence_ref="source/value"),
            calls=calls,
        )

        self.assertEqual(calls, [
            ("text", "q-1", 128),
            ("text", "a" * 64, 64),
            ("text", "b" * 64, 64),
            ("text", "source/value", 256),
            ("component", "source/value", 32),
            ("component", "q-1", 32),
        ])
        self.assertIs(rows[0][0], record)
        self.assertEqual(
            rows[0][1],
            "pcap:component-source/value:component-q-1:"
            f"{'a' * 16}:{'b' * 16}:record-0-{expected_digest[:16]}",
        )

    def test_record_serialization_exception_precedes_component_calls(self) -> None:
        calls: list[object] = []
        with self.assertRaisesRegex(RuntimeError, "record stringification failed"):
            self.project(
                self.result(records=[{"value": ExplodingRecordValue()}]),
                calls=calls,
            )

        self.assertEqual(calls, [
            ("text", "q-1", 128),
            ("text", "a" * 64, 64),
            ("text", "b" * 64, 64),
            ("text", "pcap-source", 256),
        ])


if __name__ == "__main__":
    unittest.main()
