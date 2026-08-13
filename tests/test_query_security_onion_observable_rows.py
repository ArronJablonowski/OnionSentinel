"""Characterize provenance-bound Security Onion observable row projection."""
from __future__ import annotations

from dataclasses import replace
import re
import unittest

from n8n.onion_sentinel.analysis.query import observables


class SecurityOnionObservableRowCharacterizationTests(unittest.TestCase):
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

    def project(
        self,
        query_result: object,
        response_digest: str,
        audits: dict[str, dict[str, object]],
        *,
        policy: observables.ValidationPolicy | None = None,
        calls: list[object] | None = None,
    ) -> list[tuple[object, str]]:
        return observables._security_onion_query_rows(
            query_result,
            response_digest,
            audits,
            policy or self.policy,
            self.dependencies(calls),
        )

    def test_admission_is_fail_closed_for_each_unbound_shape(self) -> None:
        digest = "a" * 64
        base = {
            "status": "ok",
            "query_id": "q-1",
            "query_digest": digest,
            "hits": [],
        }
        cases = (
            None,
            {**base, "status": "partial"},
            base,
            base,
            base,
            {**base, "query_digest": "b" * 64},
            {**base, "hits": {}},
        )
        audit_maps = (
            {"q-1": {"query_digest": digest}},
            {"q-1": {"query_digest": digest}},
            {},
            {"q-1": {"query_digest": "invalid"}},
            {"q-1": "invalid"},
            {"q-1": {"query_digest": digest}},
            {"q-1": {"query_digest": digest}},
        )
        for value, audits in zip(cases, audit_maps):
            with self.subTest(value=value, audits=audits):
                self.assertEqual(self.project(value, "r" * 64, audits), [])

    def test_rows_are_bounded_skip_malformed_hits_and_retain_source_aliases(self) -> None:
        digest = "a" * 64
        first_source = {"source": {"ip": "192.0.2.1"}}
        second_source = {"dns": {"question": {"name": "example.test"}}}
        hits = [
            "ignored",
            {"source": "invalid"},
            {"index": "index-2", "id": "id-2", "source": first_source},
            {"index": "index-3", "id": "id-3", "source": second_source},
        ]
        value = {
            "status": "ok",
            "query_id": "q-1",
            "query_digest": digest,
            "hits": hits,
        }

        rows = self.project(
            value,
            "r" * 64,
            {"q-1": {"query_digest": digest}},
        )

        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0][0], first_source)
        self.assertTrue(rows[0][1].endswith(":hit-2"))
        self.assertNotIn("id-3", rows[0][1])

    def test_evidence_reference_and_dependency_order_are_exact(self) -> None:
        calls: list[object] = []
        digest = "d" * 64
        source = {"host": {"name": "sensor"}}
        rows = self.project(
            {
                "status": "ok",
                "query_id": " query/id ",
                "query_digest": digest,
                "hits": [{"index": "index/value", "id": "id/value", "source": source}],
            },
            "response-digest-abcdefghijklmnopqrstuvwxyz",
            {" query/id ": {"query_digest": digest}},
            calls=calls,
        )

        self.assertEqual(calls, [
            ("text", " query/id ", 128),
            ("text", digest, 64),
            ("component", " query/id ", 32),
            ("component", "index/value", 32),
            ("component", "id/value", 32),
        ])
        self.assertIs(rows[0][0], source)
        self.assertEqual(
            rows[0][1],
            "so:response-digest-abcd:component- query/id :"
            f"{'d' * 20}:component-index/value:component-id/value:hit-0",
        )

    def test_negative_row_limit_preserves_python_slice_semantics(self) -> None:
        digest = "a" * 64
        hits = [
            {"index": index, "id": index, "source": {"value": index}}
            for index in range(4)
        ]
        rows = self.project(
            {
                "status": "ok",
                "query_id": "q",
                "query_digest": digest,
                "hits": hits,
            },
            "r" * 64,
            {"q": {"query_digest": digest}},
            policy=replace(self.policy, maximum_rows=-1),
        )

        self.assertEqual([row[0]["value"] for row in rows], [0, 1, 2])

    def test_component_exception_propagates_after_source_admission(self) -> None:
        digest = "a" * 64
        dependencies = observables.ValidationDependencies(
            text=lambda value, limit: str(value or "")[:limit],
            evidence_ref_component=lambda value, limit: (
                (_ for _ in ()).throw(RuntimeError("component failed"))
            ),
        )

        with self.assertRaisesRegex(RuntimeError, "component failed"):
            observables._security_onion_query_rows(
                {
                    "status": "ok",
                    "query_id": "q",
                    "query_digest": digest,
                    "hits": [{"source": {"source": {"ip": "192.0.2.1"}}}],
                },
                "r" * 64,
                {"q": {"query_digest": digest}},
                self.policy,
                dependencies,
            )


if __name__ == "__main__":
    unittest.main()
