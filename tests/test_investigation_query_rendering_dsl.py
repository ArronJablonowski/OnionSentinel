#!/usr/bin/env python3
"""Characterize deterministic investigation Query DSL composition."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import investigation_query_rendering as RENDERING  # noqa: E402


PACK_NAME = "arr238_characterization"
PACK = {
    "datasets": ["logs.alpha", "logs.beta"],
    "fields": ["@timestamp", "source.ip", "dns.question.name"],
}
OBSERVABLE_FIELDS = {
    "ips": ["source.ip", "destination.ip"],
    "domains": ["dns.question.name"],
}


def query_for(aggregation: str = "timeline") -> dict:
    return {
        "pack": PACK_NAME,
        "window": {
            "start": "2026-08-12T10:00:00.000Z",
            "end": "2026-08-12T11:00:00.000Z",
        },
        "observables": {
            "ips": ["192.0.2.10"],
            "domains": ["example.test"],
        },
        "size": 7,
        "aggregation": aggregation,
        "anchor_time": "2026-08-12T10:27:00.000Z",
    }


class InvestigationQueryDslCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        PACK["datasets"] = ["logs.alpha", "logs.beta"]
        PACK["fields"] = ["@timestamp", "source.ip", "dns.question.name"]
        self.pack_patch = mock.patch.dict(
            RENDERING.PACKS,
            {PACK_NAME: PACK},
            clear=False,
        )
        self.fields_patch = mock.patch.object(
            RENDERING,
            "pack_observable_fields",
            return_value=OBSERVABLE_FIELDS,
        )
        self.pack_patch.start()
        self.fields = self.fields_patch.start()
        self.addCleanup(self.fields_patch.stop)
        self.addCleanup(self.pack_patch.stop)

    def expected_filters(self) -> list[dict]:
        return [
            {
                "range": {
                    "@timestamp": {
                        "gte": "2026-08-12T10:00:00.000Z",
                        "lte": "2026-08-12T11:00:00.000Z",
                    }
                }
            },
            {
                "bool": {
                    "should": [
                        {"term": {"event.dataset": "logs.alpha"}},
                        {"term": {"event.dataset": "logs.beta"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            {
                "bool": {
                    "should": [
                        {"term": {"source.ip": "192.0.2.10"}},
                        {"term": {"destination.ip": "192.0.2.10"}},
                        {"term": {"dns.question.name": "example.test"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        ]

    def test_timeline_and_events_have_exact_body_shape_and_order(self) -> None:
        timeline = RENDERING.build_query_dsl(query_for("timeline"))
        events = RENDERING.build_query_dsl(query_for("events"))

        expected_query = {"bool": {"filter": self.expected_filters()}}
        self.assertEqual(
            timeline,
            {
                "size": 7,
                "track_total_hits": True,
                "timeout": "30s",
                "_source": PACK["fields"],
                "query": expected_query,
                "sort": [
                    {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                    "_shard_doc",
                ],
            },
        )
        self.assertEqual(
            events["sort"],
            [
                {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
                "_shard_doc",
            ],
        )
        self.assertEqual(
            list(timeline),
            ["size", "track_total_hits", "timeout", "_source", "query", "sort"],
        )
        self.assertEqual(list(timeline["query"]["bool"]), ["filter"])
        self.assertEqual(self.fields.call_args_list, [mock.call(PACK_NAME)] * 2)

    def test_count_omits_sort_and_replaces_size_and_source(self) -> None:
        body = RENDERING.build_query_dsl(query_for("count"))

        self.assertEqual(
            list(body),
            ["size", "track_total_hits", "timeout", "_source", "query"],
        )
        self.assertEqual(body["size"], 0)
        self.assertIs(body["_source"], False)
        self.assertNotIn("sort", body)

    def test_anchor_nearest_has_exact_score_and_sort_shape(self) -> None:
        body = RENDERING.build_query_dsl(query_for("anchor_nearest"))

        self.assertEqual(
            body["query"],
            {
                "function_score": {
                    "query": {"bool": {"filter": self.expected_filters()}},
                    "gauss": {
                        "@timestamp": {
                            "origin": "2026-08-12T10:27:00.000Z",
                            "scale": "1800s",
                            "decay": 0.5,
                        }
                    },
                    "boost_mode": "replace",
                }
            },
        )
        self.assertEqual(
            body["sort"],
            [
                {"_score": "desc"},
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                "_shard_doc",
            ],
        )

    def test_event_tuple_is_appended_after_observable_filter(self) -> None:
        query = query_for("events")
        query["event_tuple"] = {
            "source_ip": "192.0.2.10",
            "destination_port": 443,
        }

        filters = RENDERING.build_query_dsl(query)["query"]["bool"]["filter"]

        self.assertEqual(filters[:3], self.expected_filters())
        self.assertEqual(
            filters[3],
            {
                "bool": {
                    "filter": [
                        {"term": {"source.ip": "192.0.2.10"}},
                        {"term": {"destination.port": 443}},
                    ]
                }
            },
        )

    def test_empty_event_tuple_is_omitted_and_source_alias_is_preserved(self) -> None:
        query = query_for("events")
        query["event_tuple"] = {}

        body = RENDERING.build_query_dsl(query)

        self.assertEqual(len(body["query"]["bool"]["filter"]), 3)
        self.assertIs(body["_source"], RENDERING.PACKS[PACK_NAME]["fields"])

    def test_input_is_not_mutated_for_every_aggregation(self) -> None:
        for aggregation in ("count", "timeline", "events", "anchor_nearest"):
            with self.subTest(aggregation=aggregation):
                query = query_for(aggregation)
                before = copy.deepcopy(query)
                RENDERING.build_query_dsl(query)
                self.assertEqual(query, before)

    def test_failure_and_access_order_remain_fail_closed(self) -> None:
        missing_pack = query_for()
        missing_pack["pack"] = "missing"
        with self.assertRaises(KeyError):
            RENDERING.build_query_dsl(missing_pack)
        self.fields.assert_not_called()

        original_datasets = list(RENDERING.PACKS[PACK_NAME]["datasets"])
        RENDERING.PACKS[PACK_NAME]["datasets"] = []
        self.addCleanup(
            RENDERING.PACKS[PACK_NAME].__setitem__,
            "datasets",
            original_datasets,
        )
        with self.assertRaisesRegex(
            RENDERING.InvestigationQueryContractError,
            "reviewed query pack has no datasets",
        ):
            RENDERING.build_query_dsl(query_for())
        self.fields.assert_not_called()

    def test_observable_failure_precedes_anchor_timestamp_parsing(self) -> None:
        query = query_for("anchor_nearest")
        query["window"] = {"start": "invalid", "end": "also-invalid"}
        query["observables"] = {"ips": [], "domains": []}

        with self.assertRaisesRegex(
            RENDERING.InvestigationQueryContractError,
            "produced no observable query clauses",
        ):
            RENDERING.build_query_dsl(query)


if __name__ == "__main__":
    unittest.main()
