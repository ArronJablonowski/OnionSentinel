"""Characterize trusted evidence-result field projection."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import endpoint  # noqa: E402


class TracedDict(dict):
    def __init__(
        self,
        values: dict[str, object],
        *,
        label: str,
        calls: list[tuple[str, object]],
        fail_counts: dict[str, int] | None = None,
    ) -> None:
        super().__init__(values)
        self.label = label
        self.calls = calls
        self.fail_counts = dict(fail_counts or {})
        self.counts: dict[str, int] = {}

    def get(self, key: object, default: object = None) -> object:
        self.calls.append((f"{self.label}.get", key))
        name = str(key)
        self.counts[name] = self.counts.get(name, 0) + 1
        if self.fail_counts.get(name) == self.counts[name]:
            raise RuntimeError(f"{self.label} cannot read {name}")
        return super().get(key, default)


POLICY = endpoint.Policy("live-v1", "support-v1", frozenset({"ok"}))


def result(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "status": "ok",
        "semantic_valid": True,
        "hits": [],
        "rows": [],
    }
    value.update(overrides)
    return value


class EndpointRecordEvidenceResultFieldsCharacterizationTests(unittest.TestCase):
    def test_non_mapping_and_failed_status_are_noops(self) -> None:
        supplied = {"existing"}
        with mock.patch.object(endpoint, "_record_source_fields") as record:
            for value in (None, [], "value", {"status": "failed"}):
                with self.subTest(value=value):
                    endpoint._record_evidence_result_fields(
                        value, supplied, POLICY
                    )
        record.assert_not_called()
        self.assertEqual(supplied, {"existing"})

    def test_truncation_and_semantic_gates_keep_exact_access_order(self) -> None:
        calls: list[tuple[str, object]] = []
        truncated = TracedDict(
            result(
                truncated=False,
                model_projection_truncated=True,
                hits_prompt_truncated=True,
                rows_prompt_truncated=True,
            ),
            label="result",
            calls=calls,
            fail_counts={"hits_prompt_truncated": 1},
        )
        endpoint._record_evidence_result_fields(truncated, set(), POLICY)
        self.assertEqual(calls, [
            ("result.get", "status"),
            ("result.get", "truncated"),
            ("result.get", "model_projection_truncated"),
        ])

        calls.clear()
        semantic = TracedDict(
            result(semantic_valid=False), label="result", calls=calls
        )
        endpoint._record_evidence_result_fields(semantic, set(), POLICY)
        self.assertEqual(calls, [
            ("result.get", "status"),
            ("result.get", "truncated"),
            ("result.get", "model_projection_truncated"),
            ("result.get", "hits_prompt_truncated"),
            ("result.get", "rows_prompt_truncated"),
            ("result.get", "semantic_valid"),
        ])

    def test_list_collections_are_read_twice_and_nonlists_once(self) -> None:
        calls: list[tuple[str, object]] = []
        hits = [object()]
        rows = [object()]
        value = TracedDict(
            result(hits=hits, rows=rows), label="result", calls=calls
        )
        recorded: list[object] = []
        with mock.patch.object(
            endpoint,
            "_record_source_fields",
            side_effect=lambda item, _supplied: recorded.append(item),
        ):
            endpoint._record_evidence_result_fields(value, set(), POLICY)
        self.assertEqual(
            [key for label, key in calls if label == "result.get"][-4:],
            ["hits", "hits", "rows", "rows"],
        )
        self.assertEqual(recorded, rows)

        calls.clear()
        value = TracedDict(
            result(hits=tuple(hits), rows=tuple(rows)),
            label="result",
            calls=calls,
        )
        with mock.patch.object(endpoint, "_record_source_fields") as record:
            endpoint._record_evidence_result_fields(value, set(), POLICY)
        self.assertEqual(
            [key for label, key in calls if label == "result.get"][-2:],
            ["hits", "rows"],
        )
        record.assert_not_called()

    def test_hit_source_fallback_and_row_order_are_exact(self) -> None:
        calls: list[tuple[str, object]] = []
        preferred = {"process.executable": "/preferred"}
        fallback = {"process.executable": "/fallback"}
        hit_fallback = {"process.executable": "/hit"}
        hits = [
            "not-a-hit",
            TracedDict(
                {"_source": preferred, "source": fallback},
                label="hit-1",
                calls=calls,
            ),
            TracedDict(
                {"_source": None, "source": fallback},
                label="hit-2",
                calls=calls,
            ),
            TracedDict(
                {"_source": None, "source": None, **hit_fallback},
                label="hit-3",
                calls=calls,
            ),
        ]
        rows = [object(), object()]
        recorded: list[object] = []
        supplied: set[str] = set()
        with mock.patch.object(
            endpoint,
            "_record_source_fields",
            side_effect=lambda item, target: recorded.append(item)
            or target.add(f"record-{len(recorded)}"),
        ):
            endpoint._record_evidence_result_fields(
                result(hits=hits, rows=rows), supplied, POLICY
            )

        self.assertEqual(recorded, [preferred, fallback, hits[3], *rows])
        self.assertEqual(supplied, {
            "record-1", "record-2", "record-3", "record-4", "record-5",
        })
        self.assertEqual(calls, [
            ("hit-1.get", "_source"),
            ("hit-2.get", "_source"),
            ("hit-2.get", "source"),
            ("hit-3.get", "_source"),
            ("hit-3.get", "source"),
        ])

    def test_late_rows_lookup_failure_preserves_prior_hit_mutation(self) -> None:
        calls: list[tuple[str, object]] = []
        value = TracedDict(
            result(hits=[{"source": {}}], rows=[]),
            label="result",
            calls=calls,
            fail_counts={"rows": 1},
        )
        supplied: set[str] = set()
        with mock.patch.object(
            endpoint,
            "_record_source_fields",
            side_effect=lambda _item, target: target.add("hit-recorded"),
        ):
            with self.assertRaisesRegex(RuntimeError, "cannot read rows"):
                endpoint._record_evidence_result_fields(
                    value, supplied, POLICY
                )
        self.assertEqual(supplied, {"hit-recorded"})


if __name__ == "__main__":
    unittest.main()
