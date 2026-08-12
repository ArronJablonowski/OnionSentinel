#!/usr/bin/env python3
"""Characterize fail-closed investigation control-hit validation."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import investigation_query_response_control as CONTROL  # noqa: E402


ANCHOR = {
    "id": "anchor-1",
    "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
}


def control_hit(
    *,
    identifier: str = ANCHOR["id"],
    index: str = ANCHOR["index"],
    dataset: str = "suricata.alert",
) -> dict:
    return {
        "id": identifier,
        "index": index,
        "source": {
            "@timestamp": "2026-07-24T11:30:00.000Z",
            "event": {"dataset": dataset},
        },
    }


def control_result(*, positive: bool, hits: list[dict], passed: bool) -> dict:
    dsl, scope = CONTROL._expected_control_query(ANCHOR, positive)
    endpoint = CONTROL.query_endpoint(scope)
    return {
        "passed": passed,
        "query_dsl": dsl,
        "query_digest": CONTROL.canonical_digest(dsl),
        "index_scope": scope,
        "query_endpoint": endpoint,
        "execution_digest": CONTROL._expected_execution_digest(
            dsl,
            scope,
            endpoint,
        ),
        "status": "ok",
        "semantic_valid": True,
        "total_hits": len(hits),
        "total_hits_relation": "eq",
        "returned_hits": len(hits),
        "truncated": False,
        "duration_ms": 5,
        "timed_out": False,
        "took_ms": 3,
        "shards": {
            "total": 1,
            "successful": 1,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": hits,
    }


class InvestigationQueryControlHitCharacterizationTests(unittest.TestCase):
    def test_exact_positive_anchor_and_empty_negative_filter_pass(self) -> None:
        positive = control_result(
            positive=True,
            hits=[control_hit()],
            passed=True,
        )
        negative = control_result(positive=False, hits=[], passed=True)

        self.assertIs(CONTROL._validate_control(
            positive,
            anchor=ANCHOR,
            positive=True,
        ), True)
        self.assertIs(CONTROL._validate_control(
            negative,
            anchor=ANCHOR,
            positive=False,
        ), True)

    def test_authenticated_false_positive_and_negative_controls_return_false(self) -> None:
        missing_positive = control_result(positive=True, hits=[], passed=False)
        present_negative = control_result(
            positive=False,
            hits=[control_hit()],
            passed=False,
        )

        self.assertIs(CONTROL._validate_control(
            missing_positive,
            anchor=ANCHOR,
            positive=True,
        ), False)
        self.assertIs(CONTROL._validate_control(
            present_negative,
            anchor=ANCHOR,
            positive=False,
        ), False)

    def test_valid_hit_accepts_both_alert_datasets(self) -> None:
        for dataset in ("suricata.alert", "sigma.alert"):
            with self.subTest(dataset=dataset):
                self.assertIsNone(CONTROL._validate_control_hit(
                    control_hit(dataset=dataset),
                    [ANCHOR["index"]],
                    "positive anchor",
                ))

    def test_hit_identity_fails_before_scope_and_source_validation(self) -> None:
        hit = control_hit(identifier="invalid id", index="outside")
        hit["source"] = {"secret": "not-projected"}

        with self.assertRaisesRegex(
            CONTROL.InvestigationQueryContractError,
            "hit id is invalid",
        ):
            CONTROL._validate_control_hit(
                hit,
                [ANCHOR["index"]],
                "positive anchor",
            )

    def test_hit_scope_fails_before_source_validation(self) -> None:
        hit = control_hit(index="logs-endpoint.events.process-default")
        hit["source"] = {"secret": "not-projected"}

        with self.assertRaisesRegex(
            CONTROL.InvestigationQueryContractError,
            "escaped its index scope",
        ):
            CONTROL._validate_control_hit(
                hit,
                [ANCHOR["index"]],
                "positive anchor",
            )

    def test_projection_fails_before_completeness(self) -> None:
        hit = control_hit()
        hit["source"] = {"secret": "not-projected"}

        with self.assertRaisesRegex(
            CONTROL.InvestigationQueryContractError,
            "hit projection is invalid",
        ):
            CONTROL._validate_control_hit(
                hit,
                [ANCHOR["index"]],
                "positive anchor",
            )

    def test_source_requires_exactly_one_timestamp_and_dataset(self) -> None:
        candidates = (
            {"event": {"dataset": "suricata.alert"}},
            {"@timestamp": "2026-07-24T11:30:00.000Z"},
            {
                "@timestamp": [
                    "2026-07-24T11:30:00.000Z",
                    "2026-07-24T11:31:00.000Z",
                ],
                "event": {"dataset": "suricata.alert"},
            },
        )
        for source in candidates:
            with self.subTest(source=source):
                hit = control_hit()
                hit["source"] = source
                with self.assertRaisesRegex(
                    CONTROL.InvestigationQueryContractError,
                    "hit source is incomplete",
                ):
                    CONTROL._validate_control_hit(
                        hit,
                        [ANCHOR["index"]],
                        "positive anchor",
                    )

    def test_timestamp_fails_before_dataset_admission(self) -> None:
        hit = control_hit(dataset="not-an-alert")
        hit["source"]["@timestamp"] = "invalid"

        with self.assertRaisesRegex(
            CONTROL.InvestigationQueryContractError,
            "hit timestamp",
        ):
            CONTROL._validate_control_hit(
                hit,
                [ANCHOR["index"]],
                "positive anchor",
            )

    def test_unapproved_dataset_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CONTROL.InvestigationQueryContractError,
            "hit dataset is invalid",
        ):
            CONTROL._validate_control_hit(
                control_hit(dataset="zeek.dns"),
                [ANCHOR["index"]],
                "positive anchor",
            )

    def test_positive_logical_pass_requires_one_exact_anchor_hit(self) -> None:
        exact = control_hit()
        wrong_id = control_hit(identifier="other-1")
        wrong_index = control_hit(index="logs-suricata.alerts-default")
        cases = (
            ("ok", "eq", [exact], 1, 1, True),
            ("timeout", "eq", [exact], 1, 1, False),
            ("ok", "gte", [exact], 1, 1, False),
            ("ok", "eq", [wrong_id], 1, 1, False),
            ("ok", "eq", [wrong_index], 1, 1, False),
            ("ok", "eq", [exact, copy.deepcopy(exact)], 2, 2, False),
            ("ok", "eq", [exact], 2, 1, False),
            ("ok", "eq", [exact], 1, 0, False),
        )
        for status, relation, hits, total, returned, expected in cases:
            with self.subTest(
                status=status,
                relation=relation,
                total=total,
                returned=returned,
            ):
                result = {"total_hits": total, "returned_hits": returned}
                self.assertIs(CONTROL._control_logical_pass(
                    result,
                    hits,
                    relation,
                    status,
                    ANCHOR,
                    True,
                ), expected)

    def test_negative_logical_pass_requires_exact_zero(self) -> None:
        cases = (
            ("ok", "eq", [], 0, 0, True),
            ("timeout", "eq", [], 0, 0, False),
            ("ok", "gte", [], 0, 0, False),
            ("ok", "eq", [control_hit()], 1, 1, False),
            ("ok", "eq", [], 1, 0, False),
            ("ok", "eq", [], 0, 1, False),
        )
        for status, relation, hits, total, returned, expected in cases:
            with self.subTest(
                status=status,
                relation=relation,
                total=total,
                returned=returned,
            ):
                result = {"total_hits": total, "returned_hits": returned}
                self.assertIs(CONTROL._control_logical_pass(
                    result,
                    hits,
                    relation,
                    status,
                    ANCHOR,
                    False,
                ), expected)

    def test_control_validation_is_read_only(self) -> None:
        result = control_result(
            positive=True,
            hits=[control_hit()],
            passed=True,
        )
        before_result = copy.deepcopy(result)
        before_anchor = copy.deepcopy(ANCHOR)

        self.assertTrue(CONTROL._validate_control(
            result,
            anchor=ANCHOR,
            positive=True,
        ))
        self.assertEqual(result, before_result)
        self.assertEqual(ANCHOR, before_anchor)


if __name__ == "__main__":
    unittest.main()
